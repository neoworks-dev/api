// Package keys serves the account's key bundle and the public identity lookup.
// Every value is opaque to the server and stored verbatim.
package keys

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/utils"
)

const maxBundleBody = 64 << 10

type Handler struct {
	store *database.SurrealStore
}

func NewHandler(store *database.SurrealStore) *Handler {
	return &Handler{store: store}
}

// RegisterAuthenticated mounts the key endpoints behind JWT and principal
// resolution. The bundle belongs to the account itself, so install-bound
// tokens are refused; identity lookups by id are open to any principal because
// apps verify other users' signatures with them.
func (h *Handler) RegisterAuthenticated(router chi.Router) {
	router.With(middleware.RequireAccountPrincipal).Get("/api/v1/keys/bundle", h.getBundle)
	router.With(middleware.RequireAccountPrincipal).Put("/api/v1/keys/bundle", h.rotateBundle)
	router.Get("/api/v1/keys/identity", h.lookupIdentity)
	router.Get("/api/v1/users/{userId}/identity-keys", h.identityKeyHistory)
}

func (h *Handler) getBundle(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	bundle, err := h.store.GetKeyBundle(r.Context(), principal.UserID)
	if err != nil {
		respond.StoreError(w, "getBundle", err)
		return
	}
	respond.JSON(w, http.StatusOK, bundle)
}

// rotateBundle swaps the bundle for the submitted one. If-Match carries the
// version the client based the rotation on; the submitted bundle must carry the
// next version. A stale If-Match gets 409 with the current version. The
// identity keys cannot change here: a new identity enters only through the
// oauth rotation endpoint, which also writes the identity history row.
func (h *Handler) rotateBundle(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	expected, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		respond.Error(w, http.StatusPreconditionRequired, "if_match_required", "If-Match must carry the current bundle version")
		return
	}
	var next database.KeyBundle
	if !respond.Decode(w, r, &next, maxBundleBody) {
		return
	}
	if message := validateBundle(next, expected); message != "" {
		respond.Error(w, http.StatusBadRequest, "invalid_bundle", message)
		return
	}

	current, err := h.store.GetKeyBundle(r.Context(), principal.UserID)
	if err != nil {
		respond.StoreError(w, "rotateBundle", err)
		return
	}
	if current.EncPub != next.EncPub || current.SignPub != next.SignPub {
		respond.Error(w, http.StatusBadRequest, "identity_change_forbidden", "identity keys change only through key rotation")
		return
	}

	err = h.store.RotateKeyBundle(r.Context(), principal.UserID, expected, next, nil)
	var mismatch *database.ErrBundleVersionMismatch
	if errors.As(err, &mismatch) {
		respond.JSON(w, http.StatusConflict, map[string]any{
			"error": "version_mismatch", "message": "the key bundle changed", "version": mismatch.CurrentVersion,
		})
		return
	}
	if err != nil {
		respond.StoreError(w, "rotateBundle", err)
		return
	}
	next.UserID = principal.UserID
	respond.JSON(w, http.StatusOK, next)
}

func parseIfMatch(header string) (int, error) {
	value := strings.Trim(strings.TrimSpace(header), `"`)
	version, err := strconv.Atoi(value)
	if err != nil || version < 1 {
		return 0, errors.New("invalid If-Match")
	}
	return version, nil
}

func validateBundle(bundle database.KeyBundle, expected int) string {
	if bundle.Version != expected+1 {
		return "version must be the If-Match version plus one"
	}
	required := []string{bundle.AmkPassword, bundle.AmkRecovery, bundle.IdentityPrivate, bundle.EncPub, bundle.SignPub, bundle.SelfSig}
	for _, value := range required {
		if value == "" {
			return "amkPassword, amkRecovery, identityPrivate, encPub, signPub and selfSig are required"
		}
	}
	return ""
}

// lookupIdentity returns another user's public identity keys by userId, or by
// email for the account vault.
func (h *Handler) lookupIdentity(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	userID := r.URL.Query().Get("userId")
	email := r.URL.Query().Get("email")

	var identity *database.PublicIdentity
	var err error
	switch {
	case userID != "" && utils.IsLowercaseUUIDv4(userID):
		identity, err = h.store.GetPublicIdentityByUserID(r.Context(), userID)
	case email != "" && !principal.IsInstall():
		identity, err = h.store.GetPublicIdentityByEmail(r.Context(), email)
	default:
		respond.Error(w, http.StatusBadRequest, "invalid_request", "pass userId, or email from an account token")
		return
	}
	if err != nil {
		respond.StoreError(w, "lookupIdentity", err)
		return
	}
	respond.JSON(w, http.StatusOK, identity)
}

// identityKeyHistory lists every identity version of a user, oldest first, so
// verifiers can accept signatures made before a full rotation.
func (h *Handler) identityKeyHistory(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userId")
	if !utils.IsLowercaseUUIDv4(userID) {
		respond.Error(w, http.StatusBadRequest, "invalid_request", "userId must be a lowercase UUIDv4")
		return
	}
	keys, err := h.store.GetIdentityKeys(r.Context(), userID)
	if err != nil {
		respond.StoreError(w, "identityKeyHistory", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"keys": keys})
}
