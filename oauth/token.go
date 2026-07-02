package oauth

import (
	"crypto/ecdsa"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

const (
	AccessTokenTTL  = 15 * time.Minute
	RefreshTokenTTL = 30 * 24 * time.Hour
)

var (
	ErrTokenExpired = errors.New("token expired")
	ErrTokenInvalid = errors.New("token invalid")
	ErrTokenRevoked = errors.New("token revoked")
)

type Claims struct {
	jwt.RegisteredClaims
	ClientID string   `json:"client_id"`
	Scope    []string `json:"scope"`
}

// scopeReadActions are the scope actions that imply permission to decrypt a
// scope's data. Mirrors decryptableLabels in scope-keys.js.
var scopeReadActions = map[string]bool{"read": true, "write": true, "admin": true, "*": true}

// AllowsScopeLabel reports whether the granted scopes permit reading (decrypting)
// data in the given encryption label. An empty label is the legacy keyspace,
// gated by a `legacy:read` grant. The label keys the per-scope key: "entity" for
// "entity:action", or "org:entity" for "org:entity:action".
func (c *Claims) AllowsScopeLabel(label string) bool {
	if label == "" {
		label = "legacy"
	}
	for _, scope := range c.Scope {
		parts := strings.Split(scope, ":")
		var lbl, action string
		switch len(parts) {
		case 2:
			lbl, action = parts[0], parts[1]
		case 3:
			lbl, action = parts[0]+":"+parts[1], parts[2]
		default:
			continue
		}
		if lbl == label && scopeReadActions[action] {
			return true
		}
	}
	return false
}

type TokenIssuer struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	issuer     string
}

func NewTokenIssuer(privateKey *ecdsa.PrivateKey, issuer string) *TokenIssuer {
	return &TokenIssuer{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		issuer:     issuer,
	}
}

// ── Issue ─────────────────────────────────────────────────────────────────────

func (ti *TokenIssuer) IssueAccessToken(userID, clientID *models.RecordID, scopes []string) (string, *Claims, error) {
	now := time.Now()
	// A nil userID is a client_credentials token: the client acts as itself (its
	// organization), with no user subject.
	subject := ""
	if userID != nil {
		subject, _ = userID.ID.(string)
	}
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   subject,
			Issuer:    ti.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(AccessTokenTTL)),
		},
		ClientID: clientID.ID.(string),
		Scope:    scopes,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signed, err := token.SignedString(ti.privateKey)
	if err != nil {
		return "", nil, err
	}
	return signed, claims, nil
}

func (ti *TokenIssuer) IssueRefreshToken(user, client *models.RecordID, scopes []string) RefreshToken {
	now := time.Now()
	return RefreshToken{
		ID:        &models.RecordID{Table: "refresh_token", ID: uuid.NewString()},
		User:      user,
		Client:    client,
		Scopes:    scopes,
		ExpiresAt: now.Add(RefreshTokenTTL),
		CreatedAt: now,
	}
}

// IDTokenTTL bounds the FedCM/OIDC id_assertion token lifetime — short, since
// the relying party exchanges it for a session immediately.
const IDTokenTTL = 5 * time.Minute

type IDTokenClaims struct {
	jwt.RegisteredClaims
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

// IssueIDToken mints a signed OIDC ID token for a relying party. Used by the
// FedCM id_assertion endpoint: aud is the requesting client, nonce echoes the
// browser-supplied value so the RP can bind it to its request.
func (ti *TokenIssuer) IssueIDToken(userID, clientID, email, name, nonce string) (string, error) {
	now := time.Now()
	claims := &IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    ti.issuer,
			Audience:  jwt.ClaimStrings{clientID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(IDTokenTTL)),
		},
		Email: email,
		Name:  name,
		Nonce: nonce,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(ti.privateKey)
}

func (ti *TokenIssuer) IssueSessionToken(userID string) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Subject:   userID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(ti.privateKey)
}

func (ti *TokenIssuer) ValidateSessionToken(token string) (string, error) {
	parsed, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, ErrTokenInvalid
		}
		return ti.publicKey, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return "", ErrTokenExpired
		}
		return "", ErrTokenInvalid
	}
	claims, ok := parsed.Claims.(*jwt.RegisteredClaims)
	if !ok || !parsed.Valid {
		return "", ErrTokenInvalid
	}
	return claims.Subject, nil
}

// ── Verify ────────────────────────────────────────────────────────────────────

func (ti *TokenIssuer) VerifyAccessToken(raw string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(raw, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, ErrTokenInvalid
		}
		return ti.publicKey, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrTokenInvalid
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrTokenInvalid
	}
	return claims, nil
}
