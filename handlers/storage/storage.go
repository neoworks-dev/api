// Package storage reports how much of its storage quota an account uses and
// lets the user cap what one app may store.
package storage

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/storage/database"
)

const maxRequestBody = 1 << 10

type Handler struct {
	store *database.SurrealStore
}

func NewHandler(store *database.SurrealStore) *Handler {
	return &Handler{store: store}
}

// RegisterAuthenticated mounts the routes behind principal resolution. Reading
// is open to apps, which see the account's quota and total with their own
// share; the caps are the account's to set.
func (h *Handler) RegisterAuthenticated(router chi.Router) {
	router.Get("/api/v1/storage", h.usage)
	router.With(middleware.RequireAccountPrincipal).Put("/api/v1/storage/apps/{clientId}/cap", h.setCap)
}

func (h *Handler) usage(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	onlyClientID := ""
	if principal.IsInstall() {
		onlyClientID = principal.ClientID
	}
	usage, err := h.store.GetStorageUsage(r.Context(), principal.UserID, onlyClientID)
	if err != nil {
		respond.StoreError(w, "getStorageUsage", err)
		return
	}
	respond.JSON(w, http.StatusOK, usage)
}

type capRequest struct {
	CapBytes *int64 `json:"capBytes"`
}

func (h *Handler) setCap(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	var request capRequest
	if !respond.Decode(w, r, &request, maxRequestBody) {
		return
	}
	if request.CapBytes != nil && *request.CapBytes < 0 {
		respond.JSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_request", "field": "capBytes", "message": "capBytes must be 0 or more, or null to remove the cap",
		})
		return
	}
	err := h.store.SetAppStorageCap(r.Context(), principal.UserID, chi.URLParam(r, "clientId"), request.CapBytes)
	if errors.Is(err, database.ErrNotFound) {
		respond.Error(w, http.StatusNotFound, "not_found", "you have not authorized this app")
		return
	}
	if err != nil {
		respond.StoreError(w, "setAppStorageCap", err)
		return
	}
	h.usage(w, r)
}
