package oauth

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// recordIDToJSON renders a SurrealDB record id as its bare id string (no table
// prefix), matching the convention used everywhere else the API exposes ids.
// Returns the empty string for a nil pointer.
func recordIDToJSON(recordID *models.RecordID) string {
	if recordID == nil {
		return ""
	}
	return fmt.Sprintf("%v", recordID.ID)
}

type AuthorizationRequest struct {
	ClientID            string   `json:"client_id"`
	RedirectURI         string   `json:"redirect_uri"`
	ResponseType        string   `json:"response_type"`
	Scope               []string `json:"scope"`
	State               string   `json:"state"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
	// Install parameters of the requesting app installation.
	InstallID      string `json:"install_id,omitempty"`
	InstallEncPub  string `json:"install_enc_pub,omitempty"`
	InstallSignPub string `json:"install_sign_pub,omitempty"`
	InstallName    string `json:"install_name,omitempty"`
}

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	CodeVerifier string `json:"code_verifier,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

type Client struct {
	ID              *models.RecordID `json:"id"`
	Name            *string          `json:"name,omitempty"`
	SecretHash      string           `json:"secret_hash"`
	RedirectURIs    []string         `json:"redirect_uris"`
	Scopes          []string         `json:"scopes"`
	AutoGrantScopes bool             `json:"auto_grant_scopes"`
	Public          bool             `json:"public"` // PKCE-only, no secret
}

type AuthCode struct {
	Code                string           `json:"code"`
	ClientID            *models.RecordID `json:"client_id"`
	UserID              *models.RecordID `json:"user_id"`
	InstallID           string           `json:"install_id,omitempty"`
	RedirectURI         string           `json:"redirect_uri"`
	Scopes              []string         `json:"scopes"`
	CodeChallenge       string           `json:"code_challenge"`
	CodeChallengeMethod string           `json:"code_challenge_method"`
	ExpiresAt           time.Time        `json:"expires_at"`
}

type RefreshToken struct {
	ID        *models.RecordID `json:"id"`
	User      *models.RecordID `json:"user"`
	Client    *models.RecordID `json:"client"`
	Install   *models.RecordID `json:"install,omitempty"`
	Scopes    []string         `json:"scopes"`
	ExpiresAt time.Time        `json:"expires_at"`
	CreatedAt time.Time        `json:"created_at"`
	Revoked   bool             `json:"revoked"`
	Used      bool             `json:"used"`
}

type LoginChallenge struct {
	ID                  string    `json:"id"`
	ClientID            string    `json:"client_id"`
	Scopes              []string  `json:"scopes"`
	RedirectURI         string    `json:"redirect_uri"`
	State               string    `json:"state"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	InstallID           string    `json:"install_id,omitempty"`
	InstallEncPub       string    `json:"install_enc_pub,omitempty"`
	InstallSignPub      string    `json:"install_sign_pub,omitempty"`
	InstallName         string    `json:"install_name,omitempty"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type ConsentChallenge struct {
	ID                  string    `json:"id"`
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id"`
	Scopes              []string  `json:"scopes"`
	RedirectURI         string    `json:"redirect_uri"`
	State               string    `json:"state"`
	ExpiresAt           time.Time `json:"expires_at"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	InstallID           string    `json:"install_id,omitempty"`
	InstallEncPub       string    `json:"install_enc_pub,omitempty"`
	InstallSignPub      string    `json:"install_sign_pub,omitempty"`
	InstallName         string    `json:"install_name,omitempty"`
}

type Grant struct {
	User   *models.RecordID `json:"user"`
	Client *models.RecordID `json:"client"`

	Scopes    []string  `json:"scopes"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type User struct {
	ID            *models.RecordID `json:"id,omitempty"`
	FirstName     string           `json:"first_name"`
	LastName      string           `json:"last_name"`
	Email         string           `json:"email"`
	AuthHash      string           `json:"auth_hash"`
	EscrowEnabled bool             `json:"escrow_enabled"`
	CreatedAt     time.Time        `json:"created_at"`
}

type ApprovalRequest struct {
	ID                  *models.RecordID `json:"id,omitempty"`
	User                *models.RecordID `json:"user"`
	Type                string           `json:"type"`   // signin | token_refresh
	Status              string           `json:"status"` // pending | approved | denied | expired
	Client              string           `json:"client"`
	Scopes              []string         `json:"scopes"`
	RequestingLabel     *string          `json:"requesting_label,omitempty"`
	RequestingUserAgent *string          `json:"requesting_user_agent,omitempty"`
	IP                  *string          `json:"ip,omitempty"`
	Location            *string          `json:"location,omitempty"`
	LoginChallenge      *string          `json:"login_challenge,omitempty"`
	CreatedAt           time.Time        `json:"created_at"`
	DecidedAt           *time.Time       `json:"decided_at,omitempty"`
	ExpiresAt           time.Time        `json:"expires_at"`
}

// MarshalJSON emits the record-id fields as bare id strings rather than the
// driver's {Table, ID} struct, so HTTP responses never leak the internal record
// shape. The embedded alias supplies every non-id field; the named fields shadow
// the id JSON keys. DB I/O is unaffected (the driver uses CBOR, not encoding/json).
func (a ApprovalRequest) MarshalJSON() ([]byte, error) {
	type alias ApprovalRequest
	return json.Marshal(&struct {
		ID   string `json:"id,omitempty"`
		User string `json:"user"`
		*alias
	}{
		ID:    recordIDToJSON(a.ID),
		User:  recordIDToJSON(a.User),
		alias: (*alias)(&a),
	})
}

type PushToken struct {
	ID        *models.RecordID `json:"id,omitempty"`
	User      *models.RecordID `json:"user"`
	Device    *models.RecordID `json:"device,omitempty"`
	Platform  string           `json:"platform"`
	Token     string           `json:"token"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
}
