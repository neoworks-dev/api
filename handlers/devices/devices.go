// Package devices lists a user's devices and revokes them.
package devices

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/storage/database"
)

type Handler struct {
	store *database.SurrealStore
}

func NewHandler(store *database.SurrealStore) *Handler {
	return &Handler{store: store}
}

// RegisterAuthenticated mounts the device endpoints. Devices belong to the
// account, so install-bound tokens are refused.
func (h *Handler) RegisterAuthenticated(router chi.Router) {
	account := router.With(middleware.RequireAccountPrincipal)
	account.Get("/api/v1/devices", h.list)
	account.Delete("/api/v1/devices/{id}", h.revoke)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	devices, err := h.store.ListDevices(r.Context(), principal.UserID)
	if err != nil {
		respond.StoreError(w, "listDevices", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"devices": devices})
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	if err := h.store.RevokeDevice(r.Context(), principal.UserID, chi.URLParam(r, "id")); err != nil {
		respond.StoreError(w, "revokeDevice", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
