// Package renewal serves certificate renewal: an authenticator registers the
// renewal certificate the user signed for it, and later extends delegation
// certificates with the matching renewal key.
package renewal

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/storage/database"
)

const maxRequestBody = 64 << 10

type Handler struct {
	store *database.SurrealStore
}

func NewHandler(store *database.SurrealStore) *Handler {
	return &Handler{store: store}
}

// RegisterAuthenticator mounts the routes only the authenticator's token may call.
func (h *Handler) RegisterAuthenticator(router chi.Router) {
	router.Post("/api/v1/renewal-certificates", h.register)
	router.Post("/api/v1/certificates/renew", h.renew)
}

// RegisterVerifier mounts the route verifiers use to load a renewal certificate.
func (h *Handler) RegisterVerifier(router chi.Router) {
	router.Get("/api/v1/renewal-certificates/{renewalCertId}", h.get)
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	var request database.RegisterRenewalRequest
	if !respond.Decode(w, r, &request, maxRequestBody) {
		return
	}
	stored, err := h.store.RegisterRenewalCertificate(r.Context(), principal, request)
	if err != nil {
		respond.StoreError(w, "registerRenewalCertificate", err)
		return
	}
	respond.JSON(w, http.StatusCreated, stored)
}

func (h *Handler) renew(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	var request database.RenewRequest
	if !respond.Decode(w, r, &request, maxRequestBody) {
		return
	}
	renewed, err := h.store.RenewCertificate(r.Context(), principal, request)
	if err != nil {
		respond.StoreError(w, "renewCertificate", err)
		return
	}
	respond.JSON(w, http.StatusOK, renewed)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	stored, err := h.store.GetRenewalCertificate(r.Context(), principal, chi.URLParam(r, "renewalCertId"))
	if err != nil {
		respond.StoreError(w, "getRenewalCertificate", err)
		return
	}
	respond.JSON(w, http.StatusOK, stored)
}
