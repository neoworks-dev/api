// Package registry serves the public OpenSchema registry: anyone reads and
// searches published schemas, a signed-in user with the schemas:publish scope
// publishes versions of schemas they own.
package registry

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/storage/database"
)

// PublishScope is the OAuth scope that allows publishing schema versions.
const PublishScope = "schemas:publish"

const maxPublishBody = 4 << 20

type Handler struct {
	store *database.SurrealStore
}

func NewHandler(store *database.SurrealStore) *Handler {
	return &Handler{store: store}
}

// RegisterPublic mounts the read endpoints; they need no token.
func (h *Handler) RegisterPublic(router chi.Router) {
	router.Get("/api/v1/schemas", h.list)
	router.Get("/api/v1/schemas/{scope}/{name}", h.get)
	router.Get("/api/v1/schemas/{scope}/{name}/versions/{version}", h.getVersion)
}

// RegisterAuthenticated mounts publishing behind JWT and principal resolution.
func (h *Handler) RegisterAuthenticated(router chi.Router) {
	publisher := router.With(middleware.RequireAccountPrincipal, middleware.RequireScope(PublishScope))
	publisher.Post("/api/v1/schemas/{scope}/{name}/versions", h.publish)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	schemas, err := h.store.ListRegistrySchemas(r.Context(), query, limit)
	if err != nil {
		respond.StoreError(w, "listRegistrySchemas", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"schemas": schemas})
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	scope, name := chi.URLParam(r, "scope"), chi.URLParam(r, "name")
	schema, err := h.store.GetRegistrySchema(r.Context(), scope, name)
	if err != nil {
		respond.StoreError(w, "getRegistrySchema", err)
		return
	}
	versions, err := h.store.ListRegistryVersions(r.Context(), scope, name)
	if err != nil {
		respond.StoreError(w, "listRegistryVersions", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"schema": schema, "versions": versions})
}

func (h *Handler) getVersion(w http.ResponseWriter, r *http.Request) {
	version, err := h.store.GetRegistryVersion(r.Context(),
		chi.URLParam(r, "scope"), chi.URLParam(r, "name"), chi.URLParam(r, "version"))
	if err != nil {
		respond.StoreError(w, "getRegistryVersion", err)
		return
	}
	respond.JSON(w, http.StatusOK, version)
}

type publishRequest struct {
	Version     string                         `json:"version"`
	Description string                         `json:"description"`
	License     string                         `json:"license"`
	Repository  string                         `json:"repository"`
	Readme      string                         `json:"readme"`
	Targets     []string                       `json:"targets"`
	Files       []database.RegistryPublishFile `json:"files"`
}

func (h *Handler) publish(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	var request publishRequest
	if !respond.Decode(w, r, &request, maxPublishBody) {
		return
	}
	schema, err := h.store.PublishRegistryVersion(r.Context(), principal.UserID, database.RegistryPublishInput{
		Scope: chi.URLParam(r, "scope"), Name: chi.URLParam(r, "name"), Version: request.Version,
		Description: request.Description, License: request.License, Repository: request.Repository,
		Readme: request.Readme, Targets: request.Targets, Files: request.Files,
	})
	if err != nil {
		respond.StoreError(w, "publishRegistryVersion", err)
		return
	}
	respond.JSON(w, http.StatusCreated, map[string]any{"schema": schema, "version": request.Version})
}
