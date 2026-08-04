package database

import (
	"context"
	"fmt"

	"github.com/neoworks/auth/oauth"
	"github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
	"golang.org/x/crypto/bcrypt"
)

type RegisterKeyMaterialParams struct {
	UserID             string
	RecoveryWrappedAMK string
	PasswordWrappedAMK *string
	Argon2Salt         string
	Argon2Time         int
	Argon2Memory       int
	Argon2Threads      int
	Argon2Keylen       int
}

func (s *SurrealStore) CreateUserKey(ctx context.Context, params *RegisterKeyMaterialParams) (*oauth.UserKey, error) {
	fields := map[string]any{
		"user":                 models.NewRecordID("user", params.UserID),
		"recovery_wrapped_amk": params.RecoveryWrappedAMK,
		"argon2_salt":         params.Argon2Salt,
		"argon2_time":         params.Argon2Time,
		"argon2_memory":       params.Argon2Memory,
		"argon2_threads":      params.Argon2Threads,
		"argon2_keylen":       params.Argon2Keylen,
	}
	if params.PasswordWrappedAMK != nil {
		fields["password_wrapped_amk"] = *params.PasswordWrappedAMK
	}
	result, err := surrealdb.Create[oauth.UserKey](ctx, s.DB, "user_key", fields)
	if err != nil {
		return nil, fmt.Errorf("create user key: %w", err)
	}
	return result, nil
}

func (s *SurrealStore) GetUserKeyByUserID(ctx context.Context, userID string) (*oauth.UserKey, error) {
	results, err := surrealdb.Query[[]oauth.UserKey](ctx, s.DB,
		"SELECT * FROM user_key WHERE user = $user LIMIT 1",
		map[string]any{"user": models.NewRecordID("user", userID)},
	)
	if err != nil {
		return nil, fmt.Errorf("get user key: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, ErrNotFound
}

// GetUserKeyByEmail is a public lookup used to bootstrap login on a new device.
// Returns only the kdf params and password_wrapped_amk — never the recovery blob.
func (s *SurrealStore) GetUserKeyByEmail(ctx context.Context, email string) (*oauth.UserKey, error) {
	results, err := surrealdb.Query[[]oauth.UserKey](ctx, s.DB,
		"SELECT * FROM user_key WHERE user.email = $email LIMIT 1",
		map[string]any{"email": email},
	)
	if err != nil {
		return nil, fmt.Errorf("get user key by email: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, ErrNotFound
}

func (s *SurrealStore) UpdateRecoveryWrappedAMK(ctx context.Context, userID, recoveryWrappedAMK string) error {
	_, err := surrealdb.Query[[]any](ctx, s.DB,
		"UPDATE user_key SET recovery_wrapped_amk = $amk WHERE user = $user",
		map[string]any{
			"user": models.NewRecordID("user", userID),
			"amk":  recoveryWrappedAMK,
		},
	)
	return err
}

// ResetPasswordParams carries the new credentials produced by a recovery-phrase
// password reset. The AMK itself is unchanged — the client unwrapped it with the
// recovery key and re-wrapped it under a fresh password key — so only the
// password hash and the password wrapper (plus its KDF params) are replaced.
type ResetPasswordParams struct {
	UserID             string
	Password           string
	PasswordWrappedAMK string
	Argon2Salt         string
	Argon2Time         int
	Argon2Memory       int
	Argon2Threads      int
	Argon2Keylen       int
}

// ResetPassword replaces the user's password hash and the password-wrapped AMK
// in a single transaction, so a reset never leaves the login credential and the
// key wrapper out of sync. Recovery and device wrappers are left untouched.
func (s *SurrealStore) ResetPassword(ctx context.Context, params *ResetPasswordParams) error {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(params.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	_, err = surrealdb.Query[[]any](ctx, s.DB, `
		BEGIN TRANSACTION;
		UPDATE user SET password_hash = $password_hash WHERE id = $user;
		UPDATE user_key SET
			password_wrapped_amk = $password_wrapped_amk,
			argon2_salt          = $argon2_salt,
			argon2_time          = $argon2_time,
			argon2_memory        = $argon2_memory,
			argon2_threads       = $argon2_threads,
			argon2_keylen        = $argon2_keylen
		WHERE user = $user;
		COMMIT TRANSACTION;
	`, map[string]any{
		"user":                 models.NewRecordID("user", params.UserID),
		"password_hash":        string(passwordHash),
		"password_wrapped_amk": params.PasswordWrappedAMK,
		"argon2_salt":          params.Argon2Salt,
		"argon2_time":          params.Argon2Time,
		"argon2_memory":        params.Argon2Memory,
		"argon2_threads":       params.Argon2Threads,
		"argon2_keylen":        params.Argon2Keylen,
	})
	if err != nil {
		return fmt.Errorf("reset password: %w", err)
	}
	return nil
}

// SetUserPublicKey stores the account's X25519 public key (derived from the AMK
// in the Vault) and its fingerprint. Idempotent — re-publishing the same key is a
// no-op overwrite. Created lazily: the user_key row already exists from signup.
func (s *SurrealStore) SetUserPublicKey(ctx context.Context, userID, publicKey, fingerprint string) error {
	_, err := surrealdb.Query[[]any](ctx, s.DB,
		"UPDATE user_key SET public_key = $public_key, public_key_fingerprint = $fingerprint WHERE user = $user",
		map[string]any{
			"user":        models.NewRecordID("user", userID),
			"public_key":  publicKey,
			"fingerprint": fingerprint,
		},
	)
	if err != nil {
		return fmt.Errorf("set user public key: %w", err)
	}
	return nil
}

// PublicKeyEntry is a directory result: the recipient's bare user id plus their
// published account public key. Senders need both — the id to address the share
// grant, the key to seal the DEK.
type PublicKeyEntry struct {
	UserID    string `json:"user_id"`
	PublicKey string `json:"public_key"`
}

// SetUserSignPublicKey stores the account-level Ed25519 signing public key
// (derived from the AMK in the Vault). Peers verify space item envelopes and
// wrapped space keys against it. Idempotent.
func (s *SurrealStore) SetUserSignPublicKey(ctx context.Context, userID, signPublicKey string) error {
	_, err := surrealdb.Query[[]any](ctx, s.DB,
		"UPDATE user_key SET sign_public_key = $sign_public_key WHERE user = $user",
		map[string]any{
			"user":            models.NewRecordID("user", userID),
			"sign_public_key": signPublicKey,
		},
	)
	if err != nil {
		return fmt.Errorf("set user sign public key: %w", err)
	}
	return nil
}

// GetUserSignPublicKey returns a user's published Ed25519 signing key, or ""
// when none is published yet.
func (s *SurrealStore) GetUserSignPublicKey(ctx context.Context, userID string) (string, error) {
	type row struct {
		SignPublicKey *string `json:"sign_public_key"`
	}
	results, err := surrealdb.Query[[]row](ctx, s.DB,
		"SELECT sign_public_key FROM user_key WHERE user = $user LIMIT 1",
		map[string]any{"user": models.NewRecordID("user", userID)},
	)
	if err != nil {
		return "", fmt.Errorf("get user sign public key: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 && qr.Result[0].SignPublicKey != nil {
			return *qr.Result[0].SignPublicKey, nil
		}
	}
	return "", nil
}

// GetUserPublicKey looks up a single account public key by bare user id.
func (s *SurrealStore) GetUserPublicKey(ctx context.Context, userID string) (*PublicKeyEntry, error) {
	return s.lookupPublicKey(ctx,
		"SELECT user, public_key FROM user_key WHERE user = $user AND public_key != NONE LIMIT 1",
		map[string]any{"user": models.NewRecordID("user", userID)},
	)
}

// GetUserPublicKeyByEmail looks up an account public key by the owner's email.
func (s *SurrealStore) GetUserPublicKeyByEmail(ctx context.Context, email string) (*PublicKeyEntry, error) {
	return s.lookupPublicKey(ctx,
		"SELECT user, public_key FROM user_key WHERE user.email = $email AND public_key != NONE LIMIT 1",
		map[string]any{"email": email},
	)
}

// SetUserScopeKey publishes the caller's PUBLIC key for one encryption scope so
// writers (the account's other apps, or another user sharing in) can seal DEKs to
// it. Private keys are never stored. Idempotent per (user, scope).
func (s *SurrealStore) SetUserScopeKey(ctx context.Context, userID, scope, publicKey string) error {
	_, err := surrealdb.Query[[]any](ctx, s.DB,
		`UPSERT user_scope_key SET user = $user, scope = $scope, public_key = $public_key
		 WHERE user = $user AND scope = $scope`,
		map[string]any{
			"user":       models.NewRecordID("user", userID),
			"scope":      scope,
			"public_key": publicKey,
		},
	)
	if err != nil {
		return fmt.Errorf("set user scope key: %w", err)
	}
	return nil
}

// GetUserScopeKey looks up a user's published public key for one encryption scope.
func (s *SurrealStore) GetUserScopeKey(ctx context.Context, userID, scope string) (*PublicKeyEntry, error) {
	return s.lookupPublicKey(ctx,
		"SELECT user, public_key FROM user_scope_key WHERE user = $user AND scope = $scope LIMIT 1",
		map[string]any{"user": models.NewRecordID("user", userID), "scope": scope},
	)
}

// GetUserScopeKeyByEmail looks up a scope public key by the owner's email (sharing).
func (s *SurrealStore) GetUserScopeKeyByEmail(ctx context.Context, email, scope string) (*PublicKeyEntry, error) {
	return s.lookupPublicKey(ctx,
		"SELECT user, public_key FROM user_scope_key WHERE user.email = $email AND scope = $scope LIMIT 1",
		map[string]any{"email": email, "scope": scope},
	)
}

func (s *SurrealStore) lookupPublicKey(ctx context.Context, query string, params map[string]any) (*PublicKeyEntry, error) {
	type row struct {
		User      *models.RecordID `json:"user"`
		PublicKey string           `json:"public_key"`
	}
	results, err := surrealdb.Query[[]row](ctx, s.DB, query, params)
	if err != nil {
		return nil, fmt.Errorf("lookup public key: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) == 0 {
			continue
		}
		r := qr.Result[0]
		userID := ""
		if r.User != nil {
			userID = fmt.Sprintf("%v", r.User.ID)
		}
		return &PublicKeyEntry{UserID: userID, PublicKey: r.PublicKey}, nil
	}
	return nil, ErrNotFound
}

type RegisterDeviceParams struct {
	UserID     string
	PublicKey  string
	WrappedAMK string
	Name       *string
}

func (s *SurrealStore) RegisterDevice(ctx context.Context, params *RegisterDeviceParams) (*oauth.Device, error) {
	fields := map[string]any{
		"user":        models.NewRecordID("user", params.UserID),
		"public_key":  params.PublicKey,
		"wrapped_amk": params.WrappedAMK,
	}
	if params.Name != nil {
		fields["name"] = *params.Name
	}
	result, err := surrealdb.Create[oauth.Device](ctx, s.DB, "device", fields)
	if err != nil {
		return nil, fmt.Errorf("register device: %w", err)
	}
	return result, nil
}

// GetDeviceByPublicKey looks up a single device by its public key, scoped to
// the given user. Used by a returning browser to fetch its wrapped AMK.
func (s *SurrealStore) GetDeviceByPublicKey(ctx context.Context, userID, publicKey string) (*oauth.Device, error) {
	results, err := surrealdb.Query[[]oauth.Device](ctx, s.DB,
		"SELECT * FROM device WHERE user = $user AND public_key = $public_key LIMIT 1",
		map[string]any{
			"user":       models.NewRecordID("user", userID),
			"public_key": publicKey,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("get device by public key: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, ErrNotFound
}

func (s *SurrealStore) ListDevices(ctx context.Context, userID string) ([]*oauth.Device, error) {
	results, err := surrealdb.Query[[]oauth.Device](ctx, s.DB,
		"SELECT id, user, name, public_key, created_at, last_seen_at FROM device WHERE user = $user ORDER BY created_at DESC",
		map[string]any{"user": models.NewRecordID("user", userID)},
	)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	for _, qr := range *results {
		out := make([]*oauth.Device, len(qr.Result))
		for i := range qr.Result {
			out[i] = &qr.Result[i]
		}
		return out, nil
	}
	return nil, nil
}
