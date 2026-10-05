// Package handlertest drives REST handlers in tests with a chosen principal,
// bypassing token verification.
package handlertest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/database"
)

// Router is a chi router whose routes see the principal passed to Do.
type Router struct {
	chi.Router
}

// NewAuthenticated mounts the routes register adds behind a middleware that
// puts the principal of each request into its context.
func NewAuthenticated(register func(chi.Router)) *Router {
	router := chi.NewRouter()
	router.Group(func(authenticated chi.Router) {
		authenticated.Use(injectPrincipal)
		register(authenticated)
	})
	return &Router{Router: router}
}

func injectPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFor(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		ctx := middleware.ContextWithPrincipal(r.Context(), principal)
		ctx = middleware.NewContextWithClaim(ctx, claimsFor(principal, r.Header.Get("X-Test-Client")))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// claimsFor builds the claims a verified token for the principal would carry.
func claimsFor(principal access.Principal, clientID string) *oauth.Claims {
	if clientID == "" {
		clientID = "test-client"
	}
	return &oauth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: principal.UserID},
		ClientID:         clientID,
		InstallID:        principal.InstallID,
		Scope:            principal.Scopes,
	}
}

type principalKey struct{}

func principalFor(r *http.Request) (access.Principal, bool) {
	principal, ok := r.Context().Value(principalKey{}).(access.Principal)
	return principal, ok
}

// Do sends a JSON request as principal and returns the recorded response.
func (router *Router) Do(t *testing.T, principal access.Principal, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode body: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, path, reader)
	request = request.WithContext(context.WithValue(request.Context(), principalKey{}, principal))
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

// DoAnonymous sends a request that carries no principal, as an unauthenticated
// caller of a public route.
func (router *Router) DoAnonymous(t *testing.T, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
	return recorder
}

// Decode parses a recorded JSON response into target.
func Decode(t *testing.T, recorder *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.Unmarshal(recorder.Body.Bytes(), target); err != nil {
		t.Fatalf("decode %q: %v", recorder.Body.String(), err)
	}
}

// CreateUser stores an account with a version-1 key bundle and returns its
// principal with the given scopes.
func CreateUser(t *testing.T, store *database.SurrealStore, scopes ...string) access.Principal {
	t.Helper()
	userID := uuid.NewString()
	_, err := store.CreateUserWithBundle(context.Background(), &database.CreateUserParams{
		UserID:  userID,
		Email:   userID[:8] + "@example.com",
		AuthKey: "auth-key",
		Bundle: database.KeyBundle{
			Version: 1, PwhashSalt: "salt", PwhashOps: 3, PwhashMem: 67108864,
			AmkPassword: "amkp", AmkRecovery: "amkr", IdentityPrivate: "idp",
			EncPub: "enc", SignPub: "sign", SelfSig: "sig",
		},
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return access.Principal{UserID: userID, Scopes: scopes}
}
