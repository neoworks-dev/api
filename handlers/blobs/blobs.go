// Package blobs issues presigned URLs for the encrypted chunks of node blobs.
// File bytes go straight between the client and object storage; the API only
// checks access and quota.
package blobs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/storage/database"
)

const (
	presignExpiry    = 15 * time.Minute
	maxChunksPerCall = 256
	maxRequestBody   = 64 << 10
)

// Presigner creates time-limited object URLs.
type Presigner interface {
	PresignPut(ctx context.Context, key string, expiry time.Duration) (string, error)
	PresignGet(ctx context.Context, key string, expiry time.Duration) (string, error)
}

type Handler struct {
	store           *database.SurrealStore
	presigner       Presigner
	quotaBytes      int64
	storageUsedFunc func(ctx context.Context, ownerID string) (int64, error)
}

// NewHandler serves presign requests. quotaBytes is the most stored data one
// owner may hold; a value of zero or less disables the check.
func NewHandler(store *database.SurrealStore, presigner Presigner, quotaBytes int64) *Handler {
	return &Handler{store: store, presigner: presigner, quotaBytes: quotaBytes, storageUsedFunc: store.StorageUsedBytes}
}

type presignRequest struct {
	NodeID   string `json:"nodeId"`
	ObjectID string `json:"objectId"`
	Op       string `json:"op"`
	Chunks   []int  `json:"chunks"`
}

type presignedURL struct {
	Index int    `json:"index"`
	URL   string `json:"url"`
}

func (h *Handler) RegisterAuthenticated(router chi.Router) {
	router.Post("/api/v1/blobs/presign", h.presign)
}

// RegisterPublic mounts the download-only presign for link shares.
func (h *Handler) RegisterPublic(router chi.Router) {
	router.Post("/api/v1/links/{id}/presign", h.presignForLink)
}

func (h *Handler) presign(w http.ResponseWriter, r *http.Request) {
	principal, ok := middleware.PrincipalFromContext(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "invalid_token", "no principal")
		return
	}
	var request presignRequest
	if !respond.Decode(w, r, &request, maxRequestBody) {
		return
	}
	if message := validateRequest(request); message != "" {
		respond.Error(w, http.StatusBadRequest, "invalid_request", message)
		return
	}
	upload := request.Op == "put"
	target, err := h.store.AuthorizeBlob(r.Context(), principal, request.NodeID, request.ObjectID, upload)
	if err != nil {
		respond.StoreError(w, "presign", err)
		return
	}
	h.respondWithURLs(w, r, target, request.Chunks, upload)
}

// presignForLink answers a presign request for a link's subtree: download only,
// and no principal.
func (h *Handler) presignForLink(w http.ResponseWriter, r *http.Request) {
	linkID := chi.URLParam(r, "id")
	var request presignRequest
	if !respond.Decode(w, r, &request, maxRequestBody) {
		return
	}
	request.Op = "get"
	if message := validateRequest(request); message != "" {
		respond.Error(w, http.StatusBadRequest, "invalid_request", message)
		return
	}
	target, err := h.store.AuthorizeLinkBlob(r.Context(), linkID, request.NodeID, request.ObjectID)
	if err != nil {
		respond.StoreError(w, "presignLink", err)
		return
	}
	h.respondWithURLs(w, r, target, request.Chunks, false)
}

func validateRequest(request presignRequest) string {
	if request.Op != "put" && request.Op != "get" {
		return "op must be put or get"
	}
	if len(request.Chunks) == 0 || len(request.Chunks) > maxChunksPerCall {
		return fmt.Sprintf("chunks must list between 1 and %d indexes", maxChunksPerCall)
	}
	return ""
}

func (h *Handler) respondWithURLs(w http.ResponseWriter, r *http.Request, target *database.BlobTarget, chunks []int, upload bool) {
	if err := validateChunks(chunks, target.Chunks); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if upload && h.overQuota(r.Context(), w, target.OwnerID) {
		return
	}
	urls, err := h.signChunks(r.Context(), target, chunks, upload)
	if err != nil {
		respond.StoreError(w, "presign", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"urls": urls})
}

func validateChunks(chunks []int, chunkCount int) error {
	seenChunks := map[int]bool{}
	for _, index := range chunks {
		if index < 0 || index >= chunkCount {
			return errors.New("chunk index outside the blob's chunk count")
		}
		if seenChunks[index] {
			return errors.New("chunk indexes must be unique")
		}
		seenChunks[index] = true
	}
	return nil
}

// overQuota answers 403 quota_exceeded and returns true when the owner already
// stores more than the quota allows. The node's declared size is part of the
// usage by the time its chunks are uploaded.
func (h *Handler) overQuota(ctx context.Context, w http.ResponseWriter, ownerID string) bool {
	if h.quotaBytes <= 0 {
		return false
	}
	used, err := h.storageUsedFunc(ctx, ownerID)
	if err != nil {
		respond.StoreError(w, "quota", err)
		return true
	}
	if used <= h.quotaBytes {
		return false
	}
	respond.JSON(w, http.StatusForbidden, map[string]any{
		"error": "quota_exceeded", "message": "storage quota exceeded",
		"usedBytes": used, "quotaBytes": h.quotaBytes,
	})
	return true
}

func (h *Handler) signChunks(ctx context.Context, target *database.BlobTarget, chunks []int, upload bool) ([]presignedURL, error) {
	urls := make([]presignedURL, 0, len(chunks))
	for _, index := range chunks {
		key := ObjectKey(target.ObjectID, index)
		signed, err := h.sign(ctx, key, upload)
		if err != nil {
			return nil, err
		}
		urls = append(urls, presignedURL{Index: index, URL: signed})
	}
	return urls, nil
}

func (h *Handler) sign(ctx context.Context, key string, upload bool) (string, error) {
	if upload {
		return h.presigner.PresignPut(ctx, key, presignExpiry)
	}
	return h.presigner.PresignGet(ctx, key, presignExpiry)
}

// ObjectKey is the storage key of one chunk: "<objectId>/<index>".
func ObjectKey(objectID string, index int) string {
	return fmt.Sprintf("%s/%d", objectID, index)
}
