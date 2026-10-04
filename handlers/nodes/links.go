package nodes

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/respond"
)

type createLinkRequest struct {
	NodeID string `json:"nodeId"`
}

func (h *Handler) createLink(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalOf(w, r)
	if !ok {
		return
	}
	var request createLinkRequest
	if !respond.Decode(w, r, &request, maxGrantBody) {
		return
	}
	link, err := h.store.CreateLink(r.Context(), principal, request.NodeID)
	if err != nil {
		respond.StoreError(w, "createLink", err)
		return
	}
	respond.JSON(w, http.StatusOK, link)
}

func (h *Handler) revokeLink(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalOf(w, r)
	if !ok {
		return
	}
	if err := h.store.RevokeLink(r.Context(), principal, chi.URLParam(r, "id")); err != nil {
		respond.StoreError(w, "revokeLink", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) pullLink(w http.ResponseWriter, r *http.Request) {
	cursor, limit, ok := pageParameters(w, r)
	if !ok {
		return
	}
	page, err := h.store.PullLink(r.Context(), chi.URLParam(r, "id"), cursor, limit)
	if err != nil {
		respond.StoreError(w, "pullLink", err)
		return
	}
	respond.JSON(w, http.StatusOK, page)
}
