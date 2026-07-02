package database

import (
	"context"
	"fmt"

	"github.com/neoworks/auth/oauth"
	"github.com/surrealdb/surrealdb.go"
	"golang.org/x/crypto/bcrypt"
)

// CreateUserWithKeysParams holds everything needed to create a user together with
// its initial AMK (Account Master Key) wrappers and first device record.
//
// The AMK itself is generated client-side and never reaches the server in
// plaintext — only the wrapped (encrypted) forms below are stored.
type CreateUserWithKeysParams struct {
	FirstName string
	LastName  string
	Email     string
	Password  string

	RecoveryWrappedAMK string
	PasswordWrappedAMK string
	Argon2Salt         string
	Argon2Time         int
	Argon2Memory       int
	Argon2Threads      int
	Argon2Keylen       int

	DevicePublicKey  string
	DeviceWrappedAMK string
}

// CreateUserWithKeys creates the user, its user_key record (AMK wrappers + KDF
// params), and its first device record in a single transaction — so a user
// never ends up persisted without the key material needed to unlock their AMK.
func (store *SurrealStore) CreateUserWithKeys(ctx context.Context, params *CreateUserWithKeysParams) (*oauth.User, error) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(params.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	if store == nil {
		return nil, fmt.Errorf("store is nil")
	}
	if store.DB == nil {
		return nil, fmt.Errorf("database connection is nil")
	}

	results, err := surrealdb.Query[[]oauth.User](ctx, store.DB, `
		BEGIN TRANSACTION;
		LET $user = (CREATE user SET
			first_name    = $first_name,
			last_name     = $last_name,
			email         = $email,
			password_hash = $password_hash
		)[0];
		CREATE user_key SET
			user                 = $user.id,
			recovery_wrapped_amk = $recovery_wrapped_amk,
			password_wrapped_amk = $password_wrapped_amk,
			argon2_salt          = $argon2_salt,
			argon2_time          = $argon2_time,
			argon2_memory        = $argon2_memory,
			argon2_threads       = $argon2_threads,
			argon2_keylen        = $argon2_keylen;
		CREATE device SET
			user        = $user.id,
			public_key  = $device_public_key,
			wrapped_amk = $device_wrapped_amk;
		RETURN [$user];
		COMMIT TRANSACTION;
	`, map[string]any{
		"first_name":           params.FirstName,
		"last_name":            params.LastName,
		"email":                params.Email,
		"password_hash":        string(passwordHash),
		"recovery_wrapped_amk": params.RecoveryWrappedAMK,
		"password_wrapped_amk": params.PasswordWrappedAMK,
		"argon2_salt":          params.Argon2Salt,
		"argon2_time":          params.Argon2Time,
		"argon2_memory":        params.Argon2Memory,
		"argon2_threads":       params.Argon2Threads,
		"argon2_keylen":        params.Argon2Keylen,
		"device_public_key":    params.DevicePublicKey,
		"device_wrapped_amk":   params.DeviceWrappedAMK,
	})
	if err != nil {
		return nil, err
	}

	return lastResult(*results, "create user: no result returned")
}
