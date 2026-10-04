// Package installs lists connected apps, revokes them, and serves an install its
// own delegation material.
package installs

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/storage/database"
)

const maxExpiryWindowDays = 365

type Handler struct {
	store *database.SurrealStore
}

func NewHandler(store *database.SurrealStore) *Handler {
	return &Handler{store: store}
}

// RegisterAuthenticated mounts the install endpoints. Listing and revoking are
// the account's; /installs/me is the install's own.
func (h *Handler) RegisterAuthenticated(router chi.Router) {
	account := router.With(middleware.RequireAccountPrincipal)
	account.Get("/api/v1/installs", h.list)
	account.Delete("/api/v1/installs/{id}", h.revoke)
	router.With(middleware.RequireInstallPrincipal).Get("/api/v1/installs/me", h.me)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	if r.URL.Query().Has("expiringWithin") {
		h.listExpiring(w, r, principal.UserID)
		return
	}
	installs, err := h.store.ListInstalls(r.Context(), principal.UserID)
	if err != nil {
		respond.StoreError(w, "listInstalls", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"installs": installs})
}

// revoke disconnects an app: its refresh tokens stop working, its grants are
// revoked and the nodes it could read are flagged for key rotation.
func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	if err := h.store.RevokeInstall(r.Context(), principal.UserID, chi.URLParam(r, "id")); err != nil {
		respond.StoreError(w, "revokeInstall", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	grant, err := h.store.GetInstallGrant(r.Context(), principal.InstallID)
	if err != nil {
		respond.StoreError(w, "installMe", err)
		return
	}
	respond.JSON(w, http.StatusOK, grant)
}

// listExpiring answers GET /installs?expiringWithin=<days> with the user's
// active installs whose newest certificate expires within that many days.
func (h *Handler) listExpiring(w http.ResponseWriter, r *http.Request, userID string) {
	days, err := strconv.Atoi(r.URL.Query().Get("expiringWithin"))
	if err != nil || days < 1 || days > maxExpiryWindowDays {
		respond.Error(w, http.StatusBadRequest, "invalid_request", "expiringWithin must be a number of days from 1 to 365")
		return
	}
	installs, err := h.store.ListExpiringInstalls(r.Context(), userID, time.Duration(days)*24*time.Hour)
	if err != nil {
		respond.StoreError(w, "listExpiringInstalls", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"installs": installs})
}
