package middleware

import (
	"context"
	"net/http"

	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/database"
)

// InstallLookup finds an app installation by id.
type InstallLookup interface {
	GetInstall(ctx context.Context, installID string) (*database.Install, error)
}

const principalContextKey contextKey = "principal"

// PrincipalFromContext returns the principal PrincipalMiddleware resolved.
func PrincipalFromContext(ctx context.Context) (access.Principal, bool) {
	principal, ok := ctx.Value(principalContextKey).(access.Principal)
	return principal, ok
}

// ContextWithPrincipal returns a context carrying the principal, for code that
// resolves it by other means.
func ContextWithPrincipal(ctx context.Context, principal access.Principal) context.Context {
	return context.WithValue(ctx, principalContextKey, principal)
}

// PrincipalMiddleware turns verified claims into the acting principal: the
// install when the token carries one, otherwise the user. It must run after
// JWTMiddleware. Tokens without a user subject (client credentials) are
// refused, and so is a token whose install is unknown, revoked, or belongs to a
// different user or client than the token.
func PrincipalMiddleware(installs InstallLookup) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return &principalResolver{installs: installs, next: next}
	}
}

type principalResolver struct {
	installs InstallLookup
	next     http.Handler
}

func (resolver *principalResolver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claims := ClaimFromContext(r.Context())
	if claims == nil || claims.Subject == "" {
		writeAuthError(w, http.StatusForbidden, "user_required")
		return
	}
	if !installIsActive(r.Context(), resolver.installs, claims) {
		writeAuthError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	principal := access.Principal{UserID: claims.Subject, InstallID: claims.InstallID, Scopes: claims.Scope}
	resolver.next.ServeHTTP(w, r.WithContext(ContextWithPrincipal(r.Context(), principal)))
}

func installIsActive(ctx context.Context, installs InstallLookup, claims *oauth.Claims) bool {
	if claims.InstallID == "" {
		return true
	}
	install, err := installs.GetInstall(ctx, claims.InstallID)
	if err != nil {
		return false
	}
	return install.RevokedAt == nil && install.UserID == claims.Subject && install.ClientID == claims.ClientID
}

// RequireAccountPrincipal refuses install-bound tokens. Key bundles, devices and
// installs are managed by the account itself, never by an app acting for it.
func RequireAccountPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFromContext(r.Context())
		if !ok || principal.IsInstall() {
			writeAuthError(w, http.StatusForbidden, "account_token_required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireInstallPrincipal refuses tokens that are not bound to an install.
func RequireInstallPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFromContext(r.Context())
		if !ok || !principal.IsInstall() {
			writeAuthError(w, http.StatusForbidden, "install_token_required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeAuthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + code + `"}`))
}

// RequireDataAccess refuses tokens that may not touch encrypted data. An
// install-bound token acts as its install. A token without an install acts as
// the user, which only the account vault may do, so it must have been issued to
// vaultClientID.
func RequireDataAccess(vaultClientID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return &dataAccessGate{vaultClientID: vaultClientID, next: next}
	}
}

type dataAccessGate struct {
	vaultClientID string
	next          http.Handler
}

func (gate *dataAccessGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claims := ClaimFromContext(r.Context())
	if claims == nil || (claims.InstallID == "" && claims.ClientID != gate.vaultClientID) {
		writeAuthError(w, http.StatusForbidden, "install_required")
		return
	}
	gate.next.ServeHTTP(w, r)
}
