// Package spaces exposes the REST surface for E2EE spaces: the unit of sharing
// and sync for encrypted entities. The server stores wrapped keys and opaque
// envelopes only — all crypto happens client-side in the Vault.
package spaces

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/publicerr"
	"github.com/neoworks/auth/storage/database"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

type Handler struct {
	store *database.SurrealStore
}

func NewHandler(store *database.SurrealStore) *Handler {
	return &Handler{store: store}
}

func (h *Handler) Register(r chi.Router) {
	r.Post("/api/v1/spaces", h.createSpace)
	r.Get("/api/v1/spaces", h.listSpaces)
	r.Get("/api/v1/spaces/{id}", h.getSpace)
	r.Delete("/api/v1/spaces/{id}", h.deleteSpace)
	r.Post("/api/v1/spaces/{id}/members", h.inviteMember)
	r.Post("/api/v1/spaces/{id}/accept", h.acceptMembership)
	r.Delete("/api/v1/spaces/{id}/members/{user}", h.removeMember)
	r.Post("/api/v1/spaces/{id}/rotate", h.rotateKey)
	h.registerItems(r)
}

type wrappedKeyBody struct {
	Epoch      int    `json:"epoch"`
	WrappedKey string `json:"wrapped_key"`
	Signature  string `json:"signature"`
}

// createSpace makes a space plus the caller's owner membership. Idempotent for
// kind "personal" — the existing personal space for the collection is returned.
func (h *Handler) createSpace(w http.ResponseWriter, r *http.Request) {
	userID, ok := callerID(w, r)
	if !ok {
		return
	}

	var body struct {
		SpaceID    string  `json:"space_id"`
		Collection string  `json:"collection"`
		Kind       string  `json:"kind"`
		NameEnc    *string `json:"name_enc"`
		WrappedKey string  `json:"wrapped_key"`
		Signature  string  `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "invalid body", http.StatusBadRequest)
		return
	}
	if body.SpaceID == "" || body.Collection == "" || body.Kind == "" || body.WrappedKey == "" || body.Signature == "" {
		jsonErr(w, "space_id, collection, kind, wrapped_key, and signature required", http.StatusBadRequest)
		return
	}

	membership, err := h.store.Spaces.Create(r.Context(), userID, database.CreateSpaceParams{
		SpaceID:    body.SpaceID,
		Collection: body.Collection,
		Kind:       body.Kind,
		NameEnc:    body.NameEnc,
		WrappedKey: body.WrappedKey,
		Signature:  body.Signature,
	})
	if err != nil {
		writeStoreError(w, "createSpace", err)
		return
	}
	writeJSON(w, membership)
}

// listSpaces returns every membership of the caller for one collection,
// including the caller's wrapped keys — one call bootstraps all space keys.
func (h *Handler) listSpaces(w http.ResponseWriter, r *http.Request) {
	userID, ok := callerID(w, r)
	if !ok {
		return
	}
	collection := r.URL.Query().Get("collection")
	if collection == "" {
		jsonErr(w, "collection required", http.StatusBadRequest)
		return
	}

	memberships, err := h.store.Spaces.ListForUser(r.Context(), userID, collection)
	if err != nil {
		writeStoreError(w, "listSpaces", err)
		return
	}
	writeJSON(w, map[string]any{"spaces": memberships})
}

func (h *Handler) getSpace(w http.ResponseWriter, r *http.Request) {
	userID, ok := callerID(w, r)
	if !ok {
		return
	}
	detail, err := h.store.Spaces.Get(r.Context(), spaceID(r), userID)
	if err != nil {
		writeStoreError(w, "getSpace", err)
		return
	}
	writeJSON(w, detail)
}

func (h *Handler) deleteSpace(w http.ResponseWriter, r *http.Request) {
	userID, ok := callerID(w, r)
	if !ok {
		return
	}
	if err := h.store.Spaces.Delete(r.Context(), spaceID(r), userID); err != nil {
		writeStoreError(w, "deleteSpace", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// inviteMember adds a user in status "invited" with the space key sealed to
// their scope public key for every epoch still referenced by live items.
func (h *Handler) inviteMember(w http.ResponseWriter, r *http.Request) {
	userID, ok := callerID(w, r)
	if !ok {
		return
	}

	var body struct {
		UserID      string           `json:"user_id"`
		Email       string           `json:"email"`
		Role        string           `json:"role"`
		WrappedKeys []wrappedKeyBody `json:"wrapped_keys"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "invalid body", http.StatusBadRequest)
		return
	}
	if body.Role != "writer" && body.Role != "reader" {
		jsonErr(w, "role must be writer or reader", http.StatusBadRequest)
		return
	}
	if len(body.WrappedKeys) == 0 {
		jsonErr(w, "wrapped_keys required", http.StatusBadRequest)
		return
	}

	memberID, ok := h.resolveMemberID(w, r, body.UserID, body.Email)
	if !ok {
		return
	}

	wraps := make([]database.WrappedKey, 0, len(body.WrappedKeys))
	for _, wk := range body.WrappedKeys {
		wraps = append(wraps, database.WrappedKey(wk))
	}

	member, err := h.store.Spaces.InviteMember(r.Context(), spaceID(r), userID, database.InviteParams{
		MemberID:    memberID,
		Role:        body.Role,
		WrappedKeys: wraps,
	})
	if err != nil {
		writeStoreError(w, "inviteMember", err)
		return
	}
	writeJSON(w, member)
}

// acceptMembership activates the caller's invite and stores their pin
// re-signature over the wrapped key material.
func (h *Handler) acceptMembership(w http.ResponseWriter, r *http.Request) {
	userID, ok := callerID(w, r)
	if !ok {
		return
	}

	var body struct {
		AcceptSignature string `json:"accept_signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AcceptSignature == "" {
		jsonErr(w, "accept_signature required", http.StatusBadRequest)
		return
	}

	if err := h.store.Spaces.Accept(r.Context(), spaceID(r), userID, body.AcceptSignature); err != nil {
		writeStoreError(w, "acceptMembership", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// removeMember deletes a membership (owner removing someone, or self-leave).
// The response tells the owner's client it must rotate the space key now.
func (h *Handler) removeMember(w http.ResponseWriter, r *http.Request) {
	userID, ok := callerID(w, r)
	if !ok {
		return
	}
	memberID := models.NewRecordID("user", chi.URLParam(r, "user"))

	keyEpoch, err := h.store.Spaces.RemoveMember(r.Context(), spaceID(r), userID, memberID)
	if err != nil {
		writeStoreError(w, "removeMember", err)
		return
	}
	writeJSON(w, map[string]any{
		"rotation_required": true,
		"key_epoch":         keyEpoch,
	})
}

// rotateKey bumps the key epoch after a membership change. The client supplies
// one rewrap per remaining member; the expected_epoch assert loses concurrent
// rotations safely (409, refetch, retry).
func (h *Handler) rotateKey(w http.ResponseWriter, r *http.Request) {
	userID, ok := callerID(w, r)
	if !ok {
		return
	}

	var body struct {
		ExpectedEpoch int `json:"expected_epoch"`
		Rewrapped     []struct {
			UserID     string `json:"user_id"`
			WrappedKey string `json:"wrapped_key"`
			Signature  string `json:"signature"`
		} `json:"rewrapped"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "invalid body", http.StatusBadRequest)
		return
	}
	if body.ExpectedEpoch < 1 || len(body.Rewrapped) == 0 {
		jsonErr(w, "expected_epoch and rewrapped required", http.StatusBadRequest)
		return
	}

	rewraps := make([]database.MemberWrap, 0, len(body.Rewrapped))
	for _, rw := range body.Rewrapped {
		rewraps = append(rewraps, database.MemberWrap{
			UserID:     models.NewRecordID("user", rw.UserID),
			WrappedKey: rw.WrappedKey,
			Signature:  rw.Signature,
		})
	}

	newEpoch, err := h.store.Spaces.Rotate(r.Context(), spaceID(r), userID, database.RotateParams{
		ExpectedEpoch: body.ExpectedEpoch,
		Rewrapped:     rewraps,
	})
	if errors.Is(err, database.ErrStaleEpoch) {
		writeStatus(w, http.StatusConflict, map[string]any{
			"error":         "stale_epoch",
			"current_epoch": newEpoch,
		})
		return
	}
	if err != nil {
		writeStoreError(w, "rotateKey", err)
		return
	}
	writeJSON(w, map[string]any{"key_epoch": newEpoch})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (h *Handler) resolveMemberID(w http.ResponseWriter, r *http.Request, userID, email string) (models.RecordID, bool) {
	if userID != "" {
		return models.NewRecordID("user", userID), true
	}
	if email == "" {
		jsonErr(w, "user_id or email required", http.StatusBadRequest)
		return models.RecordID{}, false
	}
	user, err := h.store.GetUserByEmail(r.Context(), email)
	if errors.Is(err, database.ErrNotFound) {
		jsonErr(w, "user not found", http.StatusNotFound)
		return models.RecordID{}, false
	}
	if err != nil {
		writeStoreError(w, "resolveMemberID", err)
		return models.RecordID{}, false
	}
	return *user.ID, true
}

func spaceID(r *http.Request) models.RecordID {
	return models.NewRecordID("space", chi.URLParam(r, "id"))
}

func callerID(w http.ResponseWriter, r *http.Request) (models.RecordID, bool) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return models.RecordID{}, false
	}
	return models.NewRecordID("user", claims.Subject), true
}

// writeStoreError maps store errors to HTTP statuses. Client-safe messages
// (publicerr) pass through; everything else is scrubbed.
func writeStoreError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, database.ErrSpaceForbidden):
		jsonErr(w, "forbidden", http.StatusForbidden)
	case errors.Is(err, database.ErrCursorPurged):
		jsonErr(w, "cursor purged", http.StatusGone)
	case errors.Is(err, database.ErrNotFound):
		jsonErr(w, "not found", http.StatusNotFound)
	default:
		if msg, ok := publicerr.Message(err); ok {
			jsonErr(w, msg, http.StatusBadRequest)
			return
		}
		slog.Error(op, "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	writeStatus(w, http.StatusOK, v)
}

func writeStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("writeJSON", "err", err)
	}
}

func jsonErr(w http.ResponseWriter, msg string, status int) {
	writeStatus(w, status, map[string]string{"error": msg})
}
