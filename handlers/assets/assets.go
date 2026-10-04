// Package assets serves stored assets (images, documents) with a Redis byte
// cache in front of object storage, applying per-asset access control.
//
// Assets are user uploads, so they are served on their own origin: the api
// process runs Router on a separate listener and never serves these routes on
// the API one. A served file therefore cannot script against the API origin.
package assets

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/neoworks/auth/config"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/cache"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/objectstore"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

const (
	cacheTTL      = 10 * time.Minute
	maxUploadSize = 10 << 20 // 10 MiB
)

// inlineImageTypes are the only uploads a browser may render in place. Every
// other type, SVG included, can carry script and is served as a download.
var inlineImageTypes = map[string]bool{
	"image/png":  true,
	"image/jpeg": true,
	"image/gif":  true,
	"image/webp": true,
	"image/avif": true,
}

type Handler struct {
	surreal   *database.SurrealStore
	redis     *cache.RedisStore
	objects   *objectstore.Store
	auth      *middleware.ClientAuth
	publicURL string
}

func NewHandler(surreal *database.SurrealStore, redis *cache.RedisStore, objects *objectstore.Store, auth *middleware.ClientAuth) *Handler {
	publicURL := os.Getenv("ASSETS_PUBLIC_URL")
	if publicURL == "" {
		publicURL = config.ServiceURL("assets")
	}
	return &Handler{
		surreal:   surreal,
		redis:     redis,
		objects:   objects,
		auth:      auth,
		publicURL: strings.TrimRight(publicURL, "/"),
	}
}

// Router serves the asset routes on the asset listener.
func (h *Handler) Router() http.Handler {
	router := chi.NewRouter()
	router.Use(chimiddleware.Logger)
	router.Use(chimiddleware.Recoverer)
	router.Use(chimiddleware.RealIP)
	router.Use(corsMiddleware)
	router.Get("/assets/{id}", h.serve)
	router.Post("/assets", h.upload)
	return router
}

// corsMiddleware allows browser clients on other origins (the dashboard, the
// authenticator) to upload and read assets with an Authorization header.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type dbAsset struct {
	ID         *models.RecordID `json:"id,omitempty"`
	StorageKey string           `json:"storage_key"`
	Mime       string           `json:"mime"`
	Size       int              `json:"size"`
	Visibility string           `json:"visibility"`
	Owner      *models.RecordID `json:"owner,omitempty"`
}

// serve returns an asset's bytes. Public assets are served to anyone; private
// assets require a valid bearer token whose subject owns the asset.
func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing asset id", http.StatusBadRequest)
		return
	}

	if cached, ok := h.fromCache(r.Context(), id); ok {
		if !h.authorizeCached(r, cached) {
			return
		}
		writeBytes(w, cached.mime, cached.data)
		return
	}

	asset, err := h.loadAsset(r.Context(), id)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if asset == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !h.authorize(r, asset) {
		return
	}

	data, err := h.readObject(r.Context(), asset.StorageKey)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	h.storeCache(r.Context(), id, asset, data)
	writeBytes(w, asset.Mime, data)
}

// upload stores a new asset. Requires a valid bearer token; the caller becomes
// the owner. The `visibility` form field defaults to "private".
func (h *Handler) upload(w http.ResponseWriter, r *http.Request) {
	claim := h.bearerClaim(r)
	if claim == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		http.Error(w, "invalid upload", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxUploadSize))
	if err != nil {
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}

	contentType := header.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	visibility := r.FormValue("visibility")
	if visibility != "public" {
		visibility = "private"
	}

	storageKey := "assets/" + randomKey()
	if err := h.objects.PutObject(r.Context(), storageKey, data, contentType); err != nil {
		http.Error(w, "storage failed", http.StatusInternalServerError)
		return
	}

	asset, err := h.surreal.CreateAsset(r.Context(), database.CreateAssetParams{
		StorageKey: storageKey,
		Mime:       contentType,
		Size:       len(data),
		Visibility: visibility,
		UserID:     claim.Subject,
	})
	if err != nil || asset == nil || asset.ID == nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	id := fmt.Sprintf("%v", asset.ID.ID)
	writeJSON(w, http.StatusCreated, map[string]string{
		"id":  id,
		"url": h.publicURL + "/assets/" + id,
	})
}

// ── Access control ────────────────────────────────────────────────────────────

func (h *Handler) authorize(r *http.Request, asset *dbAsset) bool {
	if asset.Visibility == "public" {
		return true
	}
	return h.ownerAuthorized(r, asset.Owner)
}

func (h *Handler) authorizeCached(r *http.Request, c cachedEntry) bool {
	if c.visibility == "public" {
		return true
	}
	return h.ownerAuthorized(r, c.owner)
}

func (h *Handler) ownerAuthorized(r *http.Request, owner *models.RecordID) bool {
	claim := h.bearerClaim(r)
	if claim == nil {
		return false
	}
	if owner == nil || fmt.Sprintf("%v", owner.ID) != claim.Subject {
		return false
	}
	return true
}

// bearerClaim verifies the Authorization bearer token if present, returning the
// claim or nil. Revoked tokens are treated as absent.
func (h *Handler) bearerClaim(r *http.Request) *oauth.Claims {
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) <= 7 || !strings.HasPrefix(authHeader, "Bearer ") {
		return nil
	}
	claim, err := h.auth.Verify(r.Context(), authHeader[7:])
	if err != nil {
		return nil
	}
	return claim
}

// ── SurrealDB ─────────────────────────────────────────────────────────────────

func (h *Handler) loadAsset(ctx context.Context, id string) (*dbAsset, error) {
	assetRef := models.NewRecordID("asset", id)
	results, err := surrealdb.Query[[]dbAsset](ctx, h.surreal.DB,
		"SELECT * FROM $asset", map[string]any{"asset": assetRef})
	if err != nil {
		return nil, err
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			a := qr.Result[0]
			return &a, nil
		}
	}
	return nil, nil
}

// ── Cache ─────────────────────────────────────────────────────────────────────

type cachedEntry struct {
	mime       string
	data       []byte
	visibility string
	owner      *models.RecordID
}

func (h *Handler) fromCache(ctx context.Context, id string) (cachedEntry, bool) {
	raw, err := h.redis.Get(ctx, assetCacheKey(id))
	if err != nil {
		return cachedEntry{}, false
	}
	var env cacheEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return cachedEntry{}, false
	}
	entry := cachedEntry{mime: env.Mime, data: env.Data, visibility: env.Visibility}
	if env.Owner != "" {
		ref := models.NewRecordID("user", env.Owner)
		entry.owner = &ref
	}
	return entry, true
}

func (h *Handler) storeCache(ctx context.Context, id string, asset *dbAsset, data []byte) {
	env := cacheEnvelope{Mime: asset.Mime, Data: data, Visibility: asset.Visibility}
	if asset.Owner != nil {
		env.Owner = fmt.Sprintf("%v", asset.Owner.ID)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return
	}
	_ = h.redis.Set(ctx, assetCacheKey(id), raw, cacheTTL)
}

// cacheEnvelope is the JSON shape persisted in Redis.
type cacheEnvelope struct {
	Mime       string `json:"mime"`
	Data       []byte `json:"data"`
	Visibility string `json:"visibility"`
	Owner      string `json:"owner,omitempty"`
}

func (h *Handler) readObject(ctx context.Context, storageKey string) ([]byte, error) {
	obj, err := h.objects.GetObject(ctx, storageKey)
	if err != nil {
		return nil, err
	}
	defer obj.Close()
	return io.ReadAll(obj)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// writeBytes serves an asset with the uploader's content type, but never lets a
// browser run it: nosniff pins the type, the sandbox CSP strips script and
// same-origin rights from anything rendered, and non-image types download.
func writeBytes(w http.ResponseWriter, contentType string, data []byte) {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	if !isInlineImage(contentType) {
		w.Header().Set("Content-Disposition", "attachment")
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func isInlineImage(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return inlineImageTypes[mediaType]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randomKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func assetCacheKey(id string) string { return "asset:" + id }
