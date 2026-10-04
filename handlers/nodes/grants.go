package nodes

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/storage/database"
)

func (h *Handler) createGrant(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalOf(w, r)
	if !ok {
		return
	}
	var input database.GrantInput
	if !respond.Decode(w, r, &input, maxGrantBody) {
		return
	}
	grant, err := h.store.CreateAccessGrant(r.Context(), principal, chi.URLParam(r, "id"), input)
	if err != nil {
		respond.StoreError(w, "createGrant", err)
		return
	}
	respond.JSON(w, http.StatusOK, grant)
}

func (h *Handler) revokeGrant(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalOf(w, r)
	if !ok {
		return
	}
	err := h.store.RevokeAccessGrant(r.Context(), principal,
		chi.URLParam(r, "id"), chi.URLParam(r, "principalType"), chi.URLParam(r, "principalId"))
	if err != nil {
		respond.StoreError(w, "revokeGrant", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
