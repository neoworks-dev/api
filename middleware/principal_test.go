package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/database"
)

type fakeInstalls map[string]*database.Install

func (installs fakeInstalls) GetInstall(_ context.Context, installID string) (*database.Install, error) {
	install, found := installs[installID]
	if !found {
		return nil, database.ErrNotFound
	}
	return install, nil
}

func resolve(t *testing.T, installs fakeInstalls, claims *oauth.Claims) (int, string) {
	t.Helper()
	var resolvedType string
	handler := middleware.PrincipalMiddleware(installs)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := middleware.PrincipalFromContext(r.Context())
		resolvedType = principal.Type() + ":" + principal.ID()
		w.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest("GET", "/", nil)
	request = request.WithContext(middleware.NewContextWithClaim(request.Context(), claims))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Code, resolvedType
}

func claimsFor(subject, clientID, installID string) *oauth.Claims {
	return &oauth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: subject},
		ClientID:         clientID,
		InstallID:        installID,
		Scope:            []string{"@neoworks/calendar:read"},
	}
}

func TestTokenWithoutInstallActsAsTheUser(t *testing.T) {
	code, who := resolve(t, fakeInstalls{}, claimsFor("user-1", "neoworks-calendar", ""))
	if code != http.StatusOK || who != "user:user-1" {
		t.Fatalf("got %d %q", code, who)
	}
}

func TestTokenWithInstallActsAsTheInstall(t *testing.T) {
	installs := fakeInstalls{"install-1": {ID: "install-1", UserID: "user-1", ClientID: "neoworks-calendar"}}
	code, who := resolve(t, installs, claimsFor("user-1", "neoworks-calendar", "install-1"))
	if code != http.StatusOK || who != "install:install-1" {
		t.Fatalf("got %d %q", code, who)
	}
}

func TestInstallTokenIsRefusedWhenTheInstallIsUnusable(t *testing.T) {
	revokedAt := time.Now()
	installs := fakeInstalls{
		"revoked":   {ID: "revoked", UserID: "user-1", ClientID: "neoworks-calendar", RevokedAt: &revokedAt},
		"otheruser": {ID: "otheruser", UserID: "user-2", ClientID: "neoworks-calendar"},
		"otherapp":  {ID: "otherapp", UserID: "user-1", ClientID: "neoworks-photos"},
	}
	for _, installID := range []string{"revoked", "otheruser", "otherapp", "unknown"} {
		code, _ := resolve(t, installs, claimsFor("user-1", "neoworks-calendar", installID))
		if code != http.StatusUnauthorized {
			t.Errorf("install %s: got %d want 401", installID, code)
		}
	}
}

func TestTokenWithoutUserSubjectIsRefused(t *testing.T) {
	code, _ := resolve(t, fakeInstalls{}, claimsFor("", "neoworks-calendar", ""))
	if code != http.StatusForbidden {
		t.Fatalf("client-credentials token: got %d want 403", code)
	}
}

func gateStatus(t *testing.T, claims *oauth.Claims) int {
	t.Helper()
	handler := middleware.RequireDataAccess("neoworks.vault")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest("GET", "/", nil)
	request = request.WithContext(middleware.NewContextWithClaim(request.Context(), claims))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Code
}

func TestDataAccessNeedsAnInstallOrTheVaultClient(t *testing.T) {
	if code := gateStatus(t, claimsFor("user-1", "neoworks-calendar", "install-1")); code != http.StatusOK {
		t.Errorf("install token: got %d want 200", code)
	}
	if code := gateStatus(t, claimsFor("user-1", "neoworks.vault", "")); code != http.StatusOK {
		t.Errorf("vault token: got %d want 200", code)
	}
	if code := gateStatus(t, claimsFor("user-1", "neoworks-calendar", "")); code != http.StatusForbidden {
		t.Errorf("installless app token: got %d want 403", code)
	}
}

func TestRequireClientAdmitsOnlyThatClient(t *testing.T) {
	status := func(claims *oauth.Claims) int {
		handler := middleware.RequireClient("neoworks-authenticator")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		request := httptest.NewRequest("GET", "/", nil)
		request = request.WithContext(middleware.NewContextWithClaim(request.Context(), claims))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder.Code
	}
	if code := status(claimsFor("user-1", "neoworks-authenticator", "")); code != http.StatusOK {
		t.Errorf("authenticator token: got %d want 200", code)
	}
	if code := status(claimsFor("user-1", "neoworks-calendar", "")); code != http.StatusForbidden {
		t.Errorf("other client: got %d want 403", code)
	}
	if code := status(nil); code != http.StatusForbidden {
		t.Errorf("no claims: got %d want 403", code)
	}
}
