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
func recordIDToJSON(r *models.RecordID) string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%v", r.ID)
}

func recordIDsToJSON(rs []models.RecordID) []string {
	out := make([]string, len(rs))
	for i := range rs {
		out[i] = fmt.Sprintf("%v", rs[i].ID)
	}
	return out
}

type AuthorizationRequest struct {
	ClientID            string   `json:"client_id"`
	RedirectURI         string   `json:"redirect_uri"`
	ResponseType        string   `json:"response_type"`
	Scope               []string `json:"scope"`
	State               string   `json:"state"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
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
	ID               *models.RecordID `json:"id,omitempty"`
	FirstName        string           `json:"first_name"`
	LastName         string           `json:"last_name"`
	Email            string           `json:"email"`
	PasswordHash     string           `json:"password_hash"`
	StorageUsedBytes int64            `json:"storage_used_bytes"`
	CreatedAt        time.Time        `json:"created_at"`
}

type Chunk struct {
	ID         *models.RecordID `json:"id,omitempty"`
	Hash       string           `json:"hash"`
	Size       int64            `json:"size"`
	StorageKey string           `json:"storage_key"`
	RefCount   int64            `json:"ref_count"`
	CreatedAt  time.Time        `json:"created_at"`
}

// MediaRecipient is one sealed copy of a media object's DEK. The DEK is sealed
// (crypto_box_seal) to the recipient's account public key; KeyID is the bare
// recipient user id so the reader can pick its own wrapper.
type MediaRecipient struct {
	KeyID      string `json:"key_id"`
	WrappedDEK string `json:"wrapped_dek"`
}

type Media struct {
	ID         *models.RecordID  `json:"id,omitempty"`
	User       *models.RecordID  `json:"user"`
	Filename   string            `json:"filename"`
	MimeType   string            `json:"mime_type"`
	Size       int64             `json:"size"`
	Chunks     []models.RecordID `json:"chunks"`
	Recipients []MediaRecipient  `json:"recipients"`
	Version    *models.RecordID  `json:"version"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// MarshalJSON emits the record-id fields as bare id strings rather than the
// driver's {Table, ID} struct, so HTTP responses never leak the internal record
// shape. The embedded alias supplies every non-id field; the named fields shadow
// the id JSON keys. DB I/O is unaffected (the driver uses CBOR, not encoding/json).
func (m Media) MarshalJSON() ([]byte, error) {
	type alias Media
	return json.Marshal(&struct {
		ID      string   `json:"id,omitempty"`
		User    string   `json:"user"`
		Chunks  []string `json:"chunks"`
		Version string   `json:"version"`
		*alias
	}{
		ID:      recordIDToJSON(m.ID),
		User:    recordIDToJSON(m.User),
		Chunks:  recordIDsToJSON(m.Chunks),
		Version: recordIDToJSON(m.Version),
		alias:   (*alias)(&m),
	})
}

type UserKey struct {
	ID                 *models.RecordID `json:"id,omitempty"`
	User               *models.RecordID `json:"user"`
	RecoveryWrappedAMK string           `json:"recovery_wrapped_amk"`
	PasswordWrappedAMK *string          `json:"password_wrapped_amk,omitempty"`
	Argon2Salt         string           `json:"argon2_salt"`
	Argon2Time         int              `json:"argon2_time"`
	Argon2Memory       int              `json:"argon2_memory"`
	Argon2Threads      int              `json:"argon2_threads"`
	Argon2Keylen       int              `json:"argon2_keylen"`
	SocialWrappedAMK   *string          `json:"social_wrapped_amk,omitempty"`
	SocialThreshold    *int             `json:"social_threshold,omitempty"`
	SocialTotal        *int             `json:"social_total,omitempty"`
	PublicKey          *string          `json:"public_key,omitempty"`
	PublicKeyFingerprint *string        `json:"public_key_fingerprint,omitempty"`
	CreatedAt          time.Time        `json:"created_at"`
	UpdatedAt          time.Time        `json:"updated_at"`
}

type Device struct {
	ID         *models.RecordID `json:"id,omitempty"`
	User       *models.RecordID `json:"user"`
	Name       *string          `json:"name,omitempty"`
	PublicKey  string           `json:"public_key"`
	WrappedAMK string           `json:"wrapped_amk"`
	CreatedAt  time.Time        `json:"created_at"`
	LastSeenAt time.Time        `json:"last_seen_at"`
}

// MarshalJSON emits the record-id fields as bare id strings (see Media.MarshalJSON).
func (d Device) MarshalJSON() ([]byte, error) {
	type alias Device
	return json.Marshal(&struct {
		ID   string `json:"id,omitempty"`
		User string `json:"user"`
		*alias
	}{
		ID:    recordIDToJSON(d.ID),
		User:  recordIDToJSON(d.User),
		alias: (*alias)(&d),
	})
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

// MarshalJSON emits the record-id fields as bare id strings (see Media.MarshalJSON).
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

type ClientDatabase struct {
	ID        *models.RecordID `json:"id,omitempty"`
	Client    *models.RecordID `json:"client"`
	Name      string           `json:"name"`
	Namespace string           `json:"namespace"`
	DbName    string           `json:"db_name"`
	SchemaDef *map[string]any  `json:"schema_def,omitempty"`
	Status    string           `json:"status"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
}
