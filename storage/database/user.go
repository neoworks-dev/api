package database

import (
	"context"
	"fmt"

	"github.com/neoworks/auth/oauth"
	"github.com/surrealdb/surrealdb.go/pkg/models"
	"golang.org/x/crypto/bcrypt"
)

// CreateUserParams creates an account together with its first key bundle and,
// optionally, the device it signed up on. The AMK never reaches the server; the
// bundle holds only wrapped forms.
type CreateUserParams struct {
	UserID        string
	Email         string
	AuthKey       string
	EscrowEnabled bool
	FirstName     string
	LastName      string
	Bundle        KeyBundle
	Device        *RegisterDeviceParams
}

// CreateUserWithBundle creates the user, its version-1 key bundle and its first
// device in one transaction, so an account never exists without the material
// needed to unlock it. The auth key is stored as a bcrypt hash.
func (s *SurrealStore) CreateUserWithBundle(ctx context.Context, params *CreateUserParams) (*oauth.User, error) {
	authHash, err := bcrypt.GenerateFromPassword([]byte(params.AuthKey), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash auth key: %w", err)
	}

	queryParams := userCreationParams(params, string(authHash))
	statement := userCreationStatement(params.Device != nil)
	if params.Device != nil {
		addDeviceParams(queryParams, params.Device)
	}

	created, err := queryReturned[[]oauth.User](ctx, s.DB, statement, queryParams)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	if len(*created) == 0 {
		return nil, fmt.Errorf("create user: no result returned")
	}
	return &(*created)[0], nil
}

func userCreationStatement(withDevice bool) string {
	deviceStatement := ""
	if withDevice {
		deviceStatement = "CREATE $device_ref SET user = $user_ref, name = $device_name, kind = $device_kind;"
	}
	return `
		BEGIN TRANSACTION;
		LET $created = (CREATE $user_ref SET
			email          = $email,
			auth_hash      = $auth_hash,
			escrow_enabled = $escrow_enabled,
			first_name     = $first_name,
			last_name      = $last_name
		)[0];
		CREATE key_bundle SET
			user             = $user_ref,
			version          = $version,
			pwhash_salt      = $pwhash_salt,
			pwhash_ops       = $pwhash_ops,
			pwhash_mem       = $pwhash_mem,
			amk_password     = $amk_password,
			amk_recovery     = $amk_recovery,
			identity_private = $identity_private,
			enc_pub          = $enc_pub,
			sign_pub         = $sign_pub,
			self_sig         = $self_sig;
		` + deviceStatement + `
		RETURN [$created];
		COMMIT TRANSACTION;`
}

func userCreationParams(params *CreateUserParams, authHash string) map[string]any {
	bundle := params.Bundle
	return map[string]any{
		"user_ref":         models.NewRecordID("user", params.UserID),
		"email":            params.Email,
		"auth_hash":        authHash,
		"escrow_enabled":   params.EscrowEnabled,
		"first_name":       params.FirstName,
		"last_name":        params.LastName,
		"version":          bundle.Version,
		"pwhash_salt":      bundle.PwhashSalt,
		"pwhash_ops":       bundle.PwhashOps,
		"pwhash_mem":       bundle.PwhashMem,
		"amk_password":     bundle.AmkPassword,
		"amk_recovery":     bundle.AmkRecovery,
		"identity_private": bundle.IdentityPrivate,
		"enc_pub":          bundle.EncPub,
		"sign_pub":         bundle.SignPub,
		"self_sig":         bundle.SelfSig,
	}
}

// UpdateAuthHash replaces the account's password verifier with a fresh bcrypt
// hash of the given auth key.
func (s *SurrealStore) UpdateAuthHash(ctx context.Context, userID, authKey string) error {
	authHash, err := bcrypt.GenerateFromPassword([]byte(authKey), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash auth key: %w", err)
	}
	return queryExec(ctx, s.DB, "UPDATE $user SET auth_hash = $auth_hash",
		map[string]any{"user": models.NewRecordID("user", userID), "auth_hash": string(authHash)})
}
