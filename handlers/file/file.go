package file

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/objectstore"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

const maxChunkBytes = 16 << 20 // 16 MiB per chunk

type Handler struct {
	store  *database.SurrealStore
	objects *objectstore.Store
}

func NewHandler(store *database.SurrealStore, objects *objectstore.Store) *Handler {
	return &Handler{store: store, objects: objects}
}

func (h *Handler) Register(r chi.Router) {
	r.Post("/api/v1/file/check", h.checkChunks)
	r.Put("/api/v1/file/chunks/{hash}", h.uploadChunk)
	r.Get("/api/v1/file/chunks/{hash}", h.downloadChunk)
	r.Post("/api/v1/file", h.createFile)
	r.Post("/api/v1/file/batch", h.batchCreateFile)
	r.Put("/api/v1/file/{id}", h.updateFile)
	r.Post("/api/v1/file/delete", h.batchDeleteFile)
	r.Delete("/api/v1/file/{id}", h.deleteFile)
	r.Get("/api/v1/file", h.listFile)
	// Client-side embedding fill: the browser indexer pulls pending jobs, decrypts
	// + embeds locally (the server can't read the bytes), and uploads the vector.
	r.Get("/api/v1/file/embeddings/pending", h.listPendingEmbeddings)
	r.Put("/api/v1/file/{id}/embedding", h.putEmbedding)
	r.Get("/api/v1/file/{id}/manifest", h.getManifest)
	// Batch manifest: warm a whole grid page's manifests in one request.
	r.Post("/api/v1/file/manifests", h.batchManifests)
	// Single-shot thumbnail: one request returns the encrypted bytes + wrapped DEK
	// header for single-chunk objects (thumbnails), skipping the manifest hop.
	r.Get("/api/v1/file/{id}/thumbnail", h.downloadThumbnail)
	// File-scoped chunk read: authorizes by ownership OR a share grant, so a
	// recipient can fetch a shared object's chunks (the owner-scoped flat route
	// above stays for the owner's own uploads).
	r.Get("/api/v1/file/{id}/chunks/{hash}", h.downloadFileChunk)
	r.Post("/api/v1/file/{id}/share", h.shareFile)
	r.Delete("/api/v1/file/{id}/share/{recipient}", h.unshareFile)
	r.Get("/api/v1/file/{id}", h.getFile)
}

// getManifest returns a file item's chunk hashes so a client that only stored
// the file id (e.g. a contact's photo) can reassemble and decrypt it.
func (h *Handler) getManifest(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	if userID == "" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	manifest, err := h.store.GetFileManifest(r.Context(), chi.URLParam(r, "id"), userID)
	if errors.Is(err, database.ErrNotFound) {
		jsonErr(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("getManifest", "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}

	// Defense in depth behind the key-holder: for scope-tagged objects, don't hand
	// out the sealed DEK unless the token grants read on that scope. Untagged
	// (legacy) objects are gated only by the Vault's legacy:read check, so existing
	// apps that predate scopes keep working.
	if manifest.Scope != "" {
		if claims := middleware.ClaimFromContext(r.Context()); claims == nil || !claims.AllowsScopeLabel(manifest.Scope) {
			jsonErr(w, "insufficient_scope", http.StatusForbidden)
			return
		}
	}

	writeJSON(w, manifest)
}

// batchManifests resolves every readable manifest for a list of ids in one
// request, so a grid page warms its manifests without N round-trips. Unreadable
// ids are omitted rather than erroring the batch.
func (h *Handler) batchManifests(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	if userID == "" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "invalid body", http.StatusBadRequest)
		return
	}

	manifests, err := h.store.GetFileManifests(r.Context(), body.IDs, userID)
	if err != nil {
		slog.Error("batchManifests", "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}

	// Omit scope-tagged objects whose scope the token doesn't grant — same as
	// unreadable ids, so a grid page silently skips what this client can't decrypt.
	// Untagged (legacy) objects pass through; the Vault gates their decryption.
	claims := middleware.ClaimFromContext(r.Context())
	readable := manifests[:0]
	for _, m := range manifests {
		if m.Scope == "" || (claims != nil && claims.AllowsScopeLabel(m.Scope)) {
			readable = append(readable, m)
		}
	}

	writeJSON(w, readable)
}

// downloadThumbnail streams a single-chunk file object's encrypted bytes in one
// request, carrying the requester's wrapped DEK in a header so no separate
// manifest fetch is needed. Thumbnails are small (single chunk); multi-chunk
// file gets a 409 so the client falls back to the manifest path.
func (h *Handler) downloadThumbnail(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	if userID == "" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	fileID := chi.URLParam(r, "id")
	manifest, err := h.store.GetFileManifest(r.Context(), fileID, userID)
	if errors.Is(err, database.ErrNotFound) {
		jsonErr(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("downloadThumbnail: manifest", "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}
	if len(manifest.Chunks) != 1 {
		jsonErr(w, "not a single-chunk object", http.StatusConflict)
		return
	}
	// For scope-tagged objects, don't emit the wrapped DEK header unless the token
	// grants read on that scope (defense in depth behind the key-holder).
	if manifest.Scope != "" {
		if claims := middleware.ClaimFromContext(r.Context()); claims == nil || !claims.AllowsScopeLabel(manifest.Scope) {
			jsonErr(w, "insufficient_scope", http.StatusForbidden)
			return
		}
	}

	chunk, err := h.store.GetReadableChunk(r.Context(), fileID, manifest.Chunks[0].Hash, userID)
	if errors.Is(err, database.ErrNotFound) {
		jsonErr(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("downloadThumbnail: get chunk", "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}

	obj, err := h.objects.GetChunk(r.Context(), chunk.StorageKey)
	if err != nil {
		slog.Error("downloadThumbnail: object storage", "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}
	defer obj.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(chunk.Size, 10))
	w.Header().Set("X-Wrapped-DEK", manifest.WrappedDEK)
	w.Header().Set("X-File-Mime", manifest.MimeType)
	if manifest.Scope != "" {
		w.Header().Set("X-File-Scope", manifest.Scope)
	}
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	w.Header().Set("ETag", `"`+manifest.Chunks[0].Hash+`"`)
	if _, err := io.Copy(w, obj); err != nil {
		slog.Error("downloadThumbnail: stream", "err", err)
	}
}

// ── Check ─────────────────────────────────────────────────────────────────────

type chunkRef struct {
	Hash string `json:"hash"`
	Size int64  `json:"size"`
}

// checkChunks tells the client which of its chunks are not yet stored.
// The client only needs to upload the ones missing from the response.
func (h *Handler) checkChunks(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	if userID == "" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		Chunks []chunkRef `json:"chunks"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Chunks) == 0 {
		jsonErr(w, "chunks array required", http.StatusBadRequest)
		return
	}

	hashes := make([]string, len(body.Chunks))
	for i, c := range body.Chunks {
		if !validHash(c.Hash) {
			jsonErr(w, "invalid hash: "+c.Hash, http.StatusBadRequest)
			return
		}
		hashes[i] = c.Hash
	}

	known, err := h.store.CheckChunks(r.Context(), userID, hashes)
	if err != nil {
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}

	knownSet := make(map[string]bool, len(known))
	for _, h := range known {
		knownSet[h] = true
	}

	missing := make([]string, 0)
	for _, hash := range hashes {
		if !knownSet[hash] {
			missing = append(missing, hash)
		}
	}

	writeJSON(w, map[string]any{"missing_chunks": missing})
}

// ── Chunk upload ──────────────────────────────────────────────────────────────

// uploadChunk receives a single encrypted chunk, verifies its SHA-256,
// uploads to object storage, and records it in the database.
// Idempotent: uploading an already-stored chunk returns 200.
func (h *Handler) uploadChunk(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	if userID == "" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	claimedHash := chi.URLParam(r, "hash")
	if !validHash(claimedHash) {
		jsonErr(w, "invalid hash", http.StatusBadRequest)
		return
	}

	data, err := io.ReadAll(io.LimitReader(r.Body, maxChunkBytes+1))
	if err != nil {
		jsonErr(w, "read error", http.StatusBadRequest)
		return
	}
	if int64(len(data)) > maxChunkBytes {
		jsonErr(w, "chunk exceeds 16 MiB limit", http.StatusRequestEntityTooLarge)
		return
	}
	if len(data) == 0 {
		jsonErr(w, "empty body", http.StatusBadRequest)
		return
	}

	// Verify the hash matches the received bytes.
	sum := sha256.Sum256(data)
	actualHash := hex.EncodeToString(sum[:])
	if actualHash != claimedHash {
		jsonErr(w, "hash mismatch", http.StatusBadRequest)
		return
	}

	// Check if already stored for this user (idempotent).
	known, err := h.store.CheckChunks(r.Context(), userID, []string{claimedHash})
	if err != nil {
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}
	if len(known) > 0 {
		w.WriteHeader(http.StatusOK) // already exists
		return
	}

	storageKey, err := h.objects.PutChunk(r.Context(), userID, claimedHash, data)
	if err != nil {
		slog.Error("uploadChunk: object storage", "err", err)
		jsonErr(w, "object storage error", http.StatusInternalServerError)
		return
	}

	if _, err := h.store.CreateChunk(r.Context(), userID, claimedHash, int64(len(data)), storageKey); err != nil {
		slog.Error("uploadChunk: create chunk record", "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// ── Chunk download ────────────────────────────────────────────────────────────

// downloadChunk streams an encrypted chunk's bytes back to its owner.
func (h *Handler) downloadChunk(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	if userID == "" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	hash := chi.URLParam(r, "hash")
	if !validHash(hash) {
		jsonErr(w, "invalid hash", http.StatusBadRequest)
		return
	}

	chunk, err := h.store.GetChunkByHash(r.Context(), userID, hash)
	if errors.Is(err, database.ErrNotFound) {
		jsonErr(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("downloadChunk: get chunk", "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}

	obj, err := h.objects.GetChunk(r.Context(), chunk.StorageKey)
	if err != nil {
		slog.Error("downloadChunk: object storage", "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}
	defer obj.Close()

	// Chunks are content-addressed by hash and encrypted client-side, so the bytes
	// for a given URL never change. Let the browser cache them indefinitely.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(chunk.Size, 10))
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	w.Header().Set("ETag", `"`+hash+`"`)
	if _, err := io.Copy(w, obj); err != nil {
		slog.Error("downloadChunk: stream", "err", err)
	}
}

// downloadFileChunk streams an encrypted chunk to a reader authorized for the
// given file — its owner, or a user holding a share grant. The chunk must belong
// to that file. This is the read path the SDK uses for both owned and shared
// objects (it always knows the file id from the manifest).
func (h *Handler) downloadFileChunk(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	if userID == "" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	hash := chi.URLParam(r, "hash")
	if !validHash(hash) {
		jsonErr(w, "invalid hash", http.StatusBadRequest)
		return
	}

	chunk, err := h.store.GetReadableChunk(r.Context(), chi.URLParam(r, "id"), hash, userID)
	if errors.Is(err, database.ErrNotFound) {
		jsonErr(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("downloadFileChunk: get chunk", "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}

	obj, err := h.objects.GetChunk(r.Context(), chunk.StorageKey)
	if err != nil {
		slog.Error("downloadFileChunk: object storage", "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}
	defer obj.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(chunk.Size, 10))
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	w.Header().Set("ETag", `"`+hash+`"`)
	if _, err := io.Copy(w, obj); err != nil {
		slog.Error("downloadFileChunk: stream", "err", err)
	}
}

// ── Share / unshare ─────────────────────────────────────────────────────────

// shareFile grants another user read access to a file object and stores the
// recipient's sealed DEK wrapper (produced by the owner's Vault re-wrap). Owner
// only. The DEK plaintext is never seen by the server.
func (h *Handler) shareFile(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	if userID == "" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		RecipientUserID string `json:"recipient_user_id"`
		WrappedDEK      string `json:"wrapped_dek"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
		body.RecipientUserID == "" || body.WrappedDEK == "" {
		jsonErr(w, "recipient_user_id and wrapped_dek required", http.StatusBadRequest)
		return
	}
	if body.RecipientUserID == userID {
		jsonErr(w, "cannot share with self", http.StatusBadRequest)
		return
	}

	err := h.store.CreateFileShare(r.Context(), chi.URLParam(r, "id"), userID, body.RecipientUserID, body.WrappedDEK)
	if errors.Is(err, database.ErrNotFound) {
		jsonErr(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("shareFile", "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// unshareFile revokes a recipient's access: drops the grant and their wrapper.
// Owner only. Does not rotate the DEK (already-fetched data is not protected).
func (h *Handler) unshareFile(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	if userID == "" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	err := h.store.DeleteFileShare(r.Context(), chi.URLParam(r, "id"), userID, chi.URLParam(r, "recipient"))
	if errors.Is(err, database.ErrNotFound) {
		jsonErr(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("unshareFile", "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ── Create file ──────────────────────────────────────────────────────────────

// createFile finalises an upload by creating a versioned file record.
// All chunks must have been uploaded first.
func (h *Handler) createFile(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	if userID == "" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body createFileBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "invalid body", http.StatusBadRequest)
		return
	}

	file, err := h.createOne(r.Context(), userID, &body)
	if err != nil {
		writeCreateFileError(w, err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, file)
}

// batchCreateFile finalises several uploads in one round-trip. Each item is
// created independently; a per-item failure aborts with that item's error rather
// than leaving a partial batch silently.
func (h *Handler) batchCreateFile(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	if userID == "" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		Items []createFileBody `json:"items"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "invalid body", http.StatusBadRequest)
		return
	}
	if len(body.Items) == 0 {
		jsonErr(w, "items required", http.StatusBadRequest)
		return
	}

	out := make([]*oauth.File, 0, len(body.Items))
	for i := range body.Items {
		file, err := h.createOne(r.Context(), userID, &body.Items[i])
		if err != nil {
			writeCreateFileError(w, err)
			return
		}
		out = append(out, file)
	}

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, out)
}

type fileLocationBody struct {
	Lat float64 `json:"lat"`
	Lng float64 `json:"lng"`
}

type createFileBody struct {
	Filename    string             `json:"filename"`
	MimeType    string             `json:"mime_type"`
	Chunks      []chunkRef         `json:"chunks"`
	WrappedDEK  string             `json:"wrapped_dek"`
	// Scope is the encryption scope the DEK is sealed under (e.g. "photos"); absent
	// ⇒ the legacy account key. The key-holder enforces it on read.
	Scope       *string            `json:"scope"`
	ThumbnailID *string            `json:"thumbnail_id"`
	Purpose     *string            `json:"purpose"`
	// Unencrypted EXIF metadata extracted client-side from the original image.
	CaptureDate *string            `json:"capture_date"` // RFC3339
	Location    *fileLocationBody `json:"location"`
	Exif        map[string]any     `json:"exif"`
}

// createFileError carries an HTTP status alongside the message so the single and
// batch handlers can share validation.
type createFileError struct {
	status int
	msg    string
}

func (e *createFileError) Error() string { return e.msg }

func writeCreateFileError(w http.ResponseWriter, err error) {
	var ce *createFileError
	if errors.As(err, &ce) {
		jsonErr(w, ce.msg, ce.status)
		return
	}
	slog.Error("createFile", "err", err)
	jsonErr(w, "server error", http.StatusInternalServerError)
}

// createOne validates a single file spec and persists it.
func (h *Handler) createOne(ctx context.Context, userID string, body *createFileBody) (*oauth.File, error) {
	if body.Filename == "" || body.MimeType == "" || len(body.Chunks) == 0 {
		return nil, &createFileError{http.StatusBadRequest, "filename, mime_type, and chunks required"}
	}
	if body.WrappedDEK == "" {
		return nil, &createFileError{http.StatusBadRequest, "wrapped_dek required (the owner's sealed object key)"}
	}

	hashes := make([]string, len(body.Chunks))
	for i, c := range body.Chunks {
		if !validHash(c.Hash) {
			return nil, &createFileError{http.StatusBadRequest, "invalid hash: " + c.Hash}
		}
		hashes[i] = c.Hash
	}

	chunks, err := h.store.GetChunksByHashes(ctx, userID, hashes)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) || containsNotFound(err) {
			return nil, &createFileError{http.StatusUnprocessableEntity, "one or more chunks not uploaded yet"}
		}
		return nil, err
	}

	var totalSize int64
	chunkIDs := make([]models.RecordID, len(chunks))
	for i, c := range chunks {
		totalSize += c.Size
		chunkIDs[i] = *c.ID
	}

	captureDate, err := parseCaptureDate(body.CaptureDate)
	if err != nil {
		return nil, err
	}
	var location *database.GeoPoint
	if body.Location != nil {
		location = &database.GeoPoint{Lat: body.Location.Lat, Lng: body.Location.Lng}
	}

	// The owner is always the first recipient. The server stamps key_id from the
	// authenticated subject so it always matches the manifest reader check.
	return h.store.CreateFile(ctx, &database.CreateFileParams{
		UserID:      userID,
		Filename:    body.Filename,
		MimeType:    body.MimeType,
		Size:        totalSize,
		ChunkIDs:    chunkIDs,
		Recipients:  []oauth.FileRecipient{{KeyID: userID, WrappedDEK: body.WrappedDEK}},
		Scope:       body.Scope,
		ThumbnailID: body.ThumbnailID,
		Purpose:     body.Purpose,
		CaptureDate: captureDate,
		Location:    location,
		Exif:        body.Exif,
	})
}

// parseCaptureDate accepts an optional RFC3339 timestamp; absent or empty yields nil.
func parseCaptureDate(raw *string) (*time.Time, error) {
	if raw == nil || *raw == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, *raw)
	if err != nil {
		return nil, &createFileError{http.StatusBadRequest, "invalid capture_date (want RFC3339)"}
	}
	return &parsed, nil
}

// ── Update file ──────────────────────────────────────────────────────────────

// updateFile replaces the content of an existing file record (new version).
// The caller must supply parent_version_id to maintain the derived_from graph.
func (h *Handler) updateFile(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	if userID == "" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	fileID := chi.URLParam(r, "id")

	var body struct {
		ParentVersionID string     `json:"parent_version_id"`
		Filename        *string    `json:"filename"`
		MimeType        *string    `json:"mime_type"`
		Chunks          []chunkRef `json:"chunks"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "invalid body", http.StatusBadRequest)
		return
	}
	if body.ParentVersionID == "" {
		jsonErr(w, "parent_version_id required", http.StatusBadRequest)
		return
	}

	var chunkIDs []models.RecordID
	var totalSize int64

	if len(body.Chunks) > 0 {
		hashes := make([]string, len(body.Chunks))
		for i, c := range body.Chunks {
			if !validHash(c.Hash) {
				jsonErr(w, "invalid hash: "+c.Hash, http.StatusBadRequest)
				return
			}
			hashes[i] = c.Hash
		}
		chunks, err := h.store.GetChunksByHashes(r.Context(), userID, hashes)
		if err != nil {
			if containsNotFound(err) {
				jsonErr(w, "one or more chunks not uploaded yet", http.StatusUnprocessableEntity)
				return
			}
			jsonErr(w, "server error", http.StatusInternalServerError)
			return
		}
		chunkIDs = make([]models.RecordID, len(chunks))
		for i, c := range chunks {
			totalSize += c.Size
			chunkIDs[i] = *c.ID
		}
	}

	var sizePtr *int64
	if len(chunkIDs) > 0 {
		sizePtr = &totalSize
	}

	file, err := h.store.UpdateFile(r.Context(), &database.UpdateFileParams{
		FileID:         fileID,
		UserID:          userID,
		ParentVersionID: models.NewRecordID("file_version", body.ParentVersionID),
		Filename:        body.Filename,
		MimeType:        body.MimeType,
		Size:            sizePtr,
		ChunkIDs:        chunkIDs,
	})
	if errors.Is(err, database.ErrNotFound) {
		jsonErr(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("updateFile: update file record", "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, file)
}

// ── Delete file ──────────────────────────────────────────────────────────────

// deleteFile removes a file item and its full version history. Chunks no
// longer referenced by any file or version are garbage collected from object
// storage and the user's storage_used_bytes is reduced accordingly.
func (h *Handler) deleteFile(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	if userID == "" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	dead, err := h.store.DeleteFile(r.Context(), chi.URLParam(r, "id"), userID)
	if errors.Is(err, database.ErrNotFound) {
		jsonErr(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("deleteFile", "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}

	for _, gc := range dead {
		if err := h.objects.DeleteChunk(r.Context(), gc.StorageKey); err != nil {
			slog.Error("deleteFile: object storage cleanup", "err", err, "key", gc.StorageKey)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// batchDeleteFile deletes several file items in one round-trip. Deletes run
// sequentially on purpose: each DeleteFile is a multi-statement transaction that
// touches shared rows (the user's storage counter, billing periods, the chunk
// table), so running them concurrently makes SurrealDB return "resource busy".
// A per-item failure is reported in `failed` rather than aborting the rest; an
// already-deleted id counts as deleted.
func (h *Handler) batchDeleteFile(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	if userID == "" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "invalid body", http.StatusBadRequest)
		return
	}
	if len(body.IDs) == 0 {
		jsonErr(w, "ids required", http.StatusBadRequest)
		return
	}

	type failure struct {
		ID    string `json:"id"`
		Error string `json:"error"`
	}
	deleted := make([]string, 0, len(body.IDs))
	failed := make([]failure, 0)

	for _, id := range body.IDs {
		dead, err := h.store.DeleteFile(r.Context(), id, userID)
		if err != nil && !errors.Is(err, database.ErrNotFound) {
			slog.Error("batchDeleteFile", "err", err, "id", id)
			failed = append(failed, failure{ID: id, Error: "server error"})
			continue
		}
		for _, gc := range dead {
			if cerr := h.objects.DeleteChunk(r.Context(), gc.StorageKey); cerr != nil {
				slog.Error("batchDeleteFile: object storage cleanup", "err", cerr, "key", gc.StorageKey)
			}
		}
		deleted = append(deleted, id)
	}

	writeJSON(w, map[string]any{"deleted": deleted, "failed": failed})
}

// ── Embedding fill ────────────────────────────────────────────────────────────

// listPendingEmbeddings returns the caller's file that still need an embedding,
// so the in-browser indexer can download, decrypt, embed, and upload the vector.
func (h *Handler) listPendingEmbeddings(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	if userID == "" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	limit := queryInt(r, "limit", 50)
	if limit > 200 {
		limit = 200
	}

	items, err := h.store.ListPendingFileEmbeddings(r.Context(), models.NewRecordID("user", userID), limit)
	if err != nil {
		slog.Error("listPendingEmbeddings", "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, items)
}

// putEmbedding stores a client-computed vector for one of the caller's file.
// The vector is plaintext (queryable) by design — the privacy tradeoff that lets
// the server run HNSW/BM25 search over otherwise-E2E file.
func (h *Handler) putEmbedding(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	if userID == "" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	fileID := chi.URLParam(r, "id")

	// Ownership gate: GetFile is owner-scoped, so a non-owner gets ErrNotFound.
	if _, err := h.store.GetFile(r.Context(), fileID, userID); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			jsonErr(w, "not found", http.StatusNotFound)
			return
		}
		slog.Error("putEmbedding: ownership", "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}

	var body struct {
		Modality string    `json:"modality"`
		Model    string    `json:"model"`
		Dim      int       `json:"dim"`
		EmbedVer int       `json:"embed_ver"`
		Vector   []float32 `json:"vector"`
		Content  *string   `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "invalid body", http.StatusBadRequest)
		return
	}
	if len(body.Vector) == 0 {
		jsonErr(w, "vector required", http.StatusBadRequest)
		return
	}
	if body.Dim != 0 && body.Dim != len(body.Vector) {
		jsonErr(w, "dim does not match vector length", http.StatusBadRequest)
		return
	}
	modality := body.Modality
	if modality == "" {
		modality = "image"
	}

	err := h.store.SetFileEmbedding(r.Context(), &database.SetFileEmbeddingParams{
		FileID:  fileID,
		UserID:   userID,
		Modality: modality,
		Model:    body.Model,
		Dim:      len(body.Vector),
		EmbedVer: body.EmbedVer,
		Vector:   body.Vector,
		Content:  body.Content,
	})
	if err != nil {
		slog.Error("putEmbedding", "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ── List / Get ────────────────────────────────────────────────────────────────

func (h *Handler) listFile(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	if userID == "" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	limit := queryInt(r, "limit", 50)
	offset := queryInt(r, "offset", 0)
	if limit > 200 {
		limit = 200
	}

	items, err := h.store.ListFile(r.Context(), userID, limit, offset)
	if err != nil {
		slog.Error("listFile", "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, items)
}

func (h *Handler) getFile(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	if userID == "" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	item, err := h.store.GetFile(r.Context(), chi.URLParam(r, "id"), userID)
	if errors.Is(err, database.ErrNotFound) {
		jsonErr(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("getFile", "err", err)
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, item)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func mustUserID(r *http.Request) string {
	c := middleware.ClaimFromContext(r.Context())
	if c == nil {
		return ""
	}
	return c.Subject
}

func validHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	for _, c := range h {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func containsNotFound(err error) bool {
	return err != nil && (errors.Is(err, database.ErrNotFound) || isChunkMissing(err))
}

func isChunkMissing(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return len(msg) > 16 && msg[:16] == "chunk not found:"
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
