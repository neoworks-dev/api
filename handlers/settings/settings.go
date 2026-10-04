// Package settings serves per-user settings. A client writes and deletes its
// own settings; any client may read another client's settings for the same user.
package settings

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/storage/database"
)

const maxSettingBody = 256 << 10

type Handler struct {
	store *database.SurrealStore
}

func NewHandler(store *database.SurrealStore) *Handler {
	return &Handler{store: store}
}

func (h *Handler) RegisterAuthenticated(router chi.Router) {
	router.Get("/api/v1/settings", h.list)
	router.Get("/api/v1/settings/{key}", h.get)
	router.Put("/api/v1/settings/{key}", h.set)
	router.Delete("/api/v1/settings/{key}", h.delete)
}

// callerOf returns the user and the OAuth client the token was issued to.
func callerOf(w http.ResponseWriter, r *http.Request) (userID, clientID string, ok bool) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil || claims.Subject == "" {
		respond.Error(w, http.StatusUnauthorized, "invalid_token", "no user")
		return "", "", false
	}
	return claims.Subject, claims.ClientID, true
}

// clientOrDefault returns the clientId query parameter, or the caller's own client.
func clientOrDefault(r *http.Request, own string) string {
	if requested := r.URL.Query().Get("clientId"); requested != "" {
		return requested
	}
	return own
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := callerOf(w, r)
	if !ok {
		return
	}
	settings, err := h.store.ListSettings(r.Context(), userID, r.URL.Query().Get("clientId"))
	if err != nil {
		respond.StoreError(w, "listSettings", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"settings": settings})
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	userID, ownClient, ok := callerOf(w, r)
	if !ok {
		return
	}
	setting, err := h.store.GetSetting(r.Context(), userID, clientOrDefault(r, ownClient), chi.URLParam(r, "key"))
	if err != nil {
		respond.StoreError(w, "getSetting", err)
		return
	}
	respond.JSON(w, http.StatusOK, setting)
}

type setRequest struct {
	Value string `json:"value"`
}

func (h *Handler) set(w http.ResponseWriter, r *http.Request) {
	userID, clientID, ok := callerOf(w, r)
	if !ok {
		return
	}
	var request setRequest
	if !respond.Decode(w, r, &request, maxSettingBody) {
		return
	}
	setting, err := h.store.SetSetting(r.Context(), userID, clientID, chi.URLParam(r, "key"), request.Value)
	if err != nil {
		respond.StoreError(w, "setSetting", err)
		return
	}
	respond.JSON(w, http.StatusOK, setting)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	userID, clientID, ok := callerOf(w, r)
	if !ok {
		return
	}
	if err := h.store.DeleteSetting(r.Context(), userID, clientID, chi.URLParam(r, "key")); err != nil {
		respond.StoreError(w, "deleteSetting", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
