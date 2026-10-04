// Package contactcodes serves a user's contact code and resolves other users'
// codes to their public identity.
package contactcodes

import (
	"errors"
	"math"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/utils"
)

const (
	lookupsPerUserPerMinute    = 30
	lookupsPerAddressPerMinute = 60
	failedLookupsPerTenMinutes = 10
)

type Handler struct {
	store            *database.SurrealStore
	userLookups      *windowCounter
	addressLookups   *windowCounter
	userFailedLookup *windowCounter
}

func NewHandler(store *database.SurrealStore) *Handler {
	return &Handler{
		store:            store,
		userLookups:      newWindowCounter(time.Minute, lookupsPerUserPerMinute),
		addressLookups:   newWindowCounter(time.Minute, lookupsPerAddressPerMinute),
		userFailedLookup: newWindowCounter(10*time.Minute, failedLookupsPerTenMinutes),
	}
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
	address := remoteHost(r)
	if h.rateLimited(w, principal.UserID, address) {
		return
	}
	h.userLookups.record(principal.UserID)
	h.addressLookups.record(address)

	code, valid := utils.NormalizeContactCode(chi.URLParam(r, "code"))
	if !valid {
		h.userFailedLookup.record(principal.UserID)
		respond.Error(w, http.StatusBadRequest, "invalid_code", "that is not a contact code")
		return
	}
	identity, err := h.store.ResolveContactCode(r.Context(), code)
	if errors.Is(err, database.ErrNotFound) {
		h.userFailedLookup.record(principal.UserID)
	}
	if err != nil {
		respond.StoreError(w, "resolveContactCode", err)
		return
	}
	respond.JSON(w, http.StatusOK, identity)
}

func (h *Handler) rateLimited(w http.ResponseWriter, userID string, address string) bool {
	wait := h.userLookups.retryAfter(userID)
	wait = maxDuration(wait, h.addressLookups.retryAfter(address))
	wait = maxDuration(wait, h.userFailedLookup.retryAfter(userID))
	if wait <= 0 {
		return false
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
	respond.Error(w, http.StatusTooManyRequests, "rate_limited", "too many contact code lookups; try again later")
	return true
}

func maxDuration(first time.Duration, second time.Duration) time.Duration {
	if first > second {
		return first
	}
	return second
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
