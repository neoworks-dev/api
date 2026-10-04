package nodes

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/accesslog"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/storage/database"
)

func (h *Handler) createGrant(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalOf(w, r)
	if !ok {
		return
	}
	var request database.GrantRequest
	if !respond.Decode(w, r, &request, maxGrantBody) {
		return
	}
	result, err := h.store.CreateAccessGrant(r.Context(), principal, chi.URLParam(r, "id"), request)
	if err != nil {
		respond.StoreError(w, "createGrant", err)
		return
	}
	respond.JSON(w, http.StatusOK, result)
}

type revokeRequest struct {
	Entry accesslog.Entry `json:"entry"`
}

func (h *Handler) revokeGrant(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalOf(w, r)
	if !ok {
		return
	}
	var request revokeRequest
	if !respond.Decode(w, r, &request, maxGrantBody) {
		return
	}
	entry, err := h.store.RevokeAccessGrant(r.Context(), principal, chi.URLParam(r, "id"), request.Entry)
	if err != nil {
		respond.StoreError(w, "revokeGrant", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"entry": entry})
}

func (h *Handler) accessLog(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalOf(w, r)
	if !ok {
		return
	}
	entries, err := h.store.ListAccessLog(r.Context(), principal, chi.URLParam(r, "id"))
	if err != nil {
		respond.StoreError(w, "accessLog", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"entries": entries})
}
