package middleware

import (
	"context"
	"net/http"

	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/cache"
)

type ClientAuth struct {
	issuer *oauth.TokenIssuer
	redis  *cache.RedisStore
}

func ClaimFromContext(ctx context.Context) *oauth.Claims {
	claim, _ := ctx.Value(claimContextKey).(*oauth.Claims)
	return claim
}

func NewContextWithClaim(ctx context.Context, claim *oauth.Claims) context.Context {
	return context.WithValue(ctx, claimContextKey, claim)
}

func NewJWTMiddleware(issuer *oauth.TokenIssuer, redis *cache.RedisStore) *ClientAuth {
	return &ClientAuth{
		issuer: issuer,
		redis:  redis,
	}
}

// Verify validates a bearer token (signature, expiry, revocation) and returns
// its claims. Exposed so handlers can do conditional auth.
func (m *ClientAuth) Verify(ctx context.Context, token string) (*oauth.Claims, error) {
	claim, err := m.issuer.VerifyAccessToken(token)
	if err != nil {
		return nil, err
	}
	revoked, err := m.redis.IsRevoked(ctx, claim.ID)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, oauth.ErrTokenRevoked
	}
	return claim, nil
}

type contextKey string

const (
	claimContextKey contextKey = "claim"
)

func (m *ClientAuth) JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		isBearerAuth := authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer "

		if !isBearerAuth {
			http.Error(w, `{"error":"invalid_authorization_method", "message": "Only Bearer authorization is supported."}`, http.StatusUnauthorized)
			return
		}

		token := authHeader[7:]
		claim, err := m.issuer.VerifyAccessToken(token)
		if err != nil {
			http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
			return
		}

		isRevoked, err := m.redis.IsRevoked(r.Context(), claim.ID)
		if err != nil {
			http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
			return
		}
		if isRevoked {
			http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), claimContextKey, claim)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
