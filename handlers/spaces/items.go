package spaces

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/neoworks/auth/storage/database"
)

const (
	defaultPullLimit = 200
	maxPullLimit     = 500
	maxBatchItems    = 500
	maxItemVersions  = 2
)

func (h *Handler) registerItems(r chi.Router) {
	r.Get("/api/v1/spaces/{id}/items", h.pullItems)
	r.Put("/api/v1/spaces/{id}/items/{item}", h.pushItem)
	r.Post("/api/v1/spaces/{id}/items/batch", h.pushItemBatch)
	r.Get("/api/v1/spaces/{id}/items/{item}/versions", h.listItemVersions)
}

// pullItems pages the per-space sync feed: envelopes with seq > since, ordered
// by seq. stale_epoch=true restricts to rows below the current key epoch (the
// lazy re-encrypt worklist).
func (h *Handler) pullItems(w http.ResponseWriter, r *http.Request) {
	userID, ok := callerID(w, r)
	if !ok {
		return
	}

	since := queryInt(r, "since", 0)
	limit := queryInt(r, "limit", defaultPullLimit)
	if limit < 1 || limit > maxPullLimit {
		limit = maxPullLimit
	}
	staleOnly := r.URL.Query().Get("stale_epoch") == "true"

	space, ok := spaceID(w, r)
	if !ok {
		return
	}
	page, err := h.store.Spaces.PullItems(r.Context(), space, userID, since, limit, staleOnly)
	if err != nil {
		writeStoreError(w, "pullItems", err)
		return
	}
	writeJSON(w, page)
}

type pushVersionBody struct {
	VersionID string `json:"version_id"`
	Blob      string `json:"blob"`
	Sig       string `json:"sig"`
}

type pushItemBody struct {
	BaseSeq   int               `json:"base_seq"`
	KeyEpoch  int               `json:"key_epoch"`
	SchemaVer int               `json:"schema_ver"`
	Deleted   bool              `json:"deleted"`
	Blob      string            `json:"blob"`
	Sig       string            `json:"sig"`
	Versions  []pushVersionBody `json:"versions"`
}

func (b pushItemBody) validate() string {
	if b.KeyEpoch < 1 {
		return "key_epoch required"
	}
	if b.SchemaVer < 1 {
		return "schema_ver required"
	}
	if b.Sig == "" {
		return "sig required"
	}
	if !b.Deleted && b.Blob == "" {
		return "blob required"
	}
	return b.validateVersions()
}

// A content write appends its history entry in the same request: one version for
// an edit, two for a conflict merge. A tombstone carries none — its versions are
// purged with the row.
func (b pushItemBody) validateVersions() string {
	if b.Deleted && len(b.Versions) > 0 {
		return "a tombstone carries no versions"
	}
	if !b.Deleted && len(b.Versions) == 0 {
		return "versions required"
	}
	if len(b.Versions) > maxItemVersions {
		return "at most 2 versions per write"
	}
	for _, version := range b.Versions {
		if version.VersionID == "" {
			return "version_id required on every version"
		}
		if version.Blob == "" {
			return "blob required on every version"
		}
		if version.Sig == "" {
			return "sig required on every version"
		}
	}
	return ""
}

func (b pushItemBody) toParams(itemID string) database.PushItemParams {
	versions := make([]database.PushVersionParams, 0, len(b.Versions))
	for _, version := range b.Versions {
		versions = append(versions, database.PushVersionParams(version))
	}
	return database.PushItemParams{
		ItemID:    itemID,
		BaseSeq:   b.BaseSeq,
		KeyEpoch:  b.KeyEpoch,
		SchemaVer: b.SchemaVer,
		Deleted:   b.Deleted,
		Blob:      b.Blob,
		Sig:       b.Sig,
		Versions:  versions,
	}
}

// pushItem writes one envelope with optimistic concurrency on base_seq.
// Conflicts return 409 with the current row so the client can merge on device.
func (h *Handler) pushItem(w http.ResponseWriter, r *http.Request) {
	userID, ok := callerID(w, r)
	if !ok {
		return
	}

	var body pushItemBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "invalid body", http.StatusBadRequest)
		return
	}
	if msg := body.validate(); msg != "" {
		jsonErr(w, msg, http.StatusBadRequest)
		return
	}

	space, ok := spaceID(w, r)
	if !ok {
		return
	}
	itemID, ok := itemUUID(w, r)
	if !ok {
		return
	}

	outcome, err := h.store.Spaces.PushItem(r.Context(), space, userID, body.toParams(itemID))
	if err != nil && outcome == nil {
		writeStoreError(w, "pushItem", err)
		return
	}

	switch {
	case errors.Is(err, database.ErrSeqConflict):
		writeStatus(w, http.StatusConflict, map[string]any{
			"error":   "conflict",
			"current": outcome.Current,
		})
	case errors.Is(err, database.ErrStaleEpoch):
		writeStatus(w, http.StatusConflict, map[string]any{
			"error":         "stale_epoch",
			"current_epoch": outcome.CurrentEpoch,
		})
	case errors.Is(err, database.ErrSpaceForbidden):
		jsonErr(w, "forbidden", http.StatusForbidden)
	case err != nil:
		writeStoreError(w, "pushItem", err)
	default:
		writeJSON(w, map[string]any{
			"item_id":   outcome.ItemID,
			"seq":       outcome.Seq,
			"key_epoch": body.KeyEpoch,
		})
	}
}

// pushItemBatch writes many envelopes, one transaction each — a single
// conflict doesn't fail the import. Per-item outcomes come back in order.
func (h *Handler) pushItemBatch(w http.ResponseWriter, r *http.Request) {
	userID, ok := callerID(w, r)
	if !ok {
		return
	}

	var body struct {
		Items []struct {
			ItemID string `json:"item_id"`
			pushItemBody
		} `json:"items"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "invalid body", http.StatusBadRequest)
		return
	}
	if len(body.Items) == 0 || len(body.Items) > maxBatchItems {
		jsonErr(w, "items must contain 1-500 entries", http.StatusBadRequest)
		return
	}

	params := make([]database.PushItemParams, 0, len(body.Items))
	for _, item := range body.Items {
		if item.ItemID == "" {
			jsonErr(w, "item_id required on every item", http.StatusBadRequest)
			return
		}
		if msg := item.validate(); msg != "" {
			jsonErr(w, msg+" (item "+item.ItemID+")", http.StatusBadRequest)
			return
		}
		params = append(params, item.toParams(item.ItemID))
	}

	space, ok := spaceID(w, r)
	if !ok {
		return
	}
	outcomes, err := h.store.Spaces.PushItems(r.Context(), space, userID, params)
	if err != nil {
		writeStoreError(w, "pushItemBatch", err)
		return
	}
	writeJSON(w, map[string]any{"results": outcomes})
}

// listItemVersions returns the encrypted history of one item, oldest first.
func (h *Handler) listItemVersions(w http.ResponseWriter, r *http.Request) {
	userID, ok := callerID(w, r)
	if !ok {
		return
	}
	space, ok := spaceID(w, r)
	if !ok {
		return
	}
	itemID, ok := itemUUID(w, r)
	if !ok {
		return
	}

	versions, err := h.store.Spaces.ListItemVersions(r.Context(), space, userID, itemID)
	if err != nil {
		writeStoreError(w, "listItemVersions", err)
		return
	}
	writeJSON(w, map[string]any{"versions": versions})
}

// itemUUID parses the {item} path parameter. Item ids are client-chosen uuids —
// the AAD binds one before upload and the record key embeds it — so anything
// else is a client error.
func itemUUID(w http.ResponseWriter, r *http.Request) (string, bool) {
	raw := chi.URLParam(r, "item")
	if _, err := uuid.FromString(raw); err != nil {
		jsonErr(w, "item id must be a uuid", http.StatusBadRequest)
		return "", false
	}
	return raw, true
}

func queryInt(r *http.Request, name string, fallback int) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}
