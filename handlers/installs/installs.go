// Package installs lists connected apps, revokes them, and serves an install its
// own delegation material. A connected app is an app the user authorized, with
// its installs, who is behind it and what it stores in the account.
package installs

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/config"
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
	account.Get("/api/v1/connected-apps", h.listConnectedApps)
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

// connectedApp is what the user sees of an app they authorized.
type connectedApp struct {
	*database.PublicApp
	LogoURL          *string            `json:"logoUrl"`
	Scopes           []string           `json:"scopes"`
	AuthorizedAt     time.Time          `json:"authorizedAt"`
	LastAuthorizedAt time.Time          `json:"lastAuthorizedAt"`
	Installs         []database.Install `json:"installs"`
	Storage          appStorage         `json:"storage"`
}

type appStorage struct {
	UsedBytes int64  `json:"usedBytes"`
	CapBytes  *int64 `json:"capBytes"`
}

func (h *Handler) listConnectedApps(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	apps, err := h.store.ListConnectedApps(r.Context(), principal.UserID)
	if err != nil {
		respond.StoreError(w, "listConnectedApps", err)
		return
	}
	views := make([]connectedApp, 0, len(apps))
	for _, app := range apps {
		views = append(views, connectedAppView(app))
	}
	respond.JSON(w, http.StatusOK, map[string]any{"apps": views})
}

func connectedAppView(app database.ConnectedApp) connectedApp {
	view := connectedApp{
		PublicApp: app.App, Scopes: app.Scopes, AuthorizedAt: app.AuthorizedAt, LastAuthorizedAt: app.LastAuthorizedAt,
		Installs: app.Installs, Storage: appStorage{UsedBytes: app.Storage.UsedBytes, CapBytes: app.Storage.CapBytes},
	}
	if app.App.LogoAssetID != nil {
		url := config.AssetURL(*app.App.LogoAssetID)
		view.LogoURL = &url
	}
	return view
}
