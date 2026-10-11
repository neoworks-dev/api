// Package contactcodes serves a user's contact code and resolves other users'
// codes to their public identity.
package contactcodes

import (
	"errors"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/ratelimit"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/utils"
)

const (
	lookupsPerUserPerMinute    = 30
	lookupsPerAddressPerMinute = 60
	failedLookupsPerTenMinutes = 10
)

type Handler struct {
	store   *database.SurrealStore
	limiter lookupLimiter
}

// NewHandler serves the contact code routes. Lookups are limited in the memory
// of this process until WithCounter shares the counters.
func NewHandler(store *database.SurrealStore) *Handler {
	return &Handler{store: store, limiter: lookupLimiter{counter: ratelimit.NewMemoryCounter()}}
}

// WithCounter counts lookups in a counter shared by every instance of the api.
func (h *Handler) WithCounter(counter ratelimit.Counter) *Handler {
	h.limiter = lookupLimiter{counter: counter}
	return h
}

// RegisterAuthenticated mounts the code endpoints behind JWT and principal
// resolution. Apps read the code and resolve other users' codes; replacing the
// code is an account action.
func (h *Handler) RegisterAuthenticated(router chi.Router) {
	router.Get("/api/v1/contact-code", h.getCode)
	router.With(middleware.RequireAccountPrincipal).Post("/api/v1/contact-code/regenerate", h.regenerateCode)
	router.Get("/api/v1/contact-codes/{code}", h.resolveCode)
}

func (h *Handler) getCode(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	code, err := h.store.GetContactCode(r.Context(), principal.UserID)
	if err != nil {
		respond.StoreError(w, "getContactCode", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]string{"code": code})
}

func (h *Handler) regenerateCode(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	code, err := h.store.RegenerateContactCode(r.Context(), principal.UserID)
	if err != nil {
		respond.StoreError(w, "regenerateContactCode", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]string{"code": code})
}

func (h *Handler) resolveCode(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	if wait := h.limiter.wait(r.Context(), principal.UserID, remoteHost(r)); wait > 0 {
		writeLimited(w, wait)
		return
	}

	code, valid := utils.NormalizeContactCode(chi.URLParam(r, "code"))
	if !valid {
		h.limiter.recordFailure(r.Context(), principal.UserID)
		respond.Error(w, http.StatusBadRequest, "invalid_code", "that is not a contact code")
		return
	}
	identity, err := h.store.ResolveContactCode(r.Context(), code)
	if errors.Is(err, database.ErrNotFound) {
		h.limiter.recordFailure(r.Context(), principal.UserID)
	}
	if err != nil {
		respond.StoreError(w, "resolveContactCode", err)
		return
	}
	respond.JSON(w, http.StatusOK, identity)
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
