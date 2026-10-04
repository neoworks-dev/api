package oauth

import (
	"crypto/ecdsa"
	"errors"
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
	// InstallID binds the token to one app installation; empty for the account vault.
	InstallID string `json:"install_id,omitempty"`
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
	return ti.IssueAccessTokenForInstall(userID, clientID, "", scopes)
}

// IssueAccessTokenForInstall mints an access token bound to an app installation.
// An empty installID yields an unbound token.
func (ti *TokenIssuer) IssueAccessTokenForInstall(userID, clientID *models.RecordID, installID string, scopes []string) (string, *Claims, error) {
	now := time.Now()
	// A nil userID is a client_credentials token: the client acts as itself, with
	// no user subject.
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
		ClientID:  clientID.ID.(string),
		Scope:     scopes,
		InstallID: installID,
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
