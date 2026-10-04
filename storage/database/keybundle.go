package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/surrealdb/surrealdb.go/pkg/models"
	"golang.org/x/crypto/bcrypt"
)

// ErrBundleVersionMismatch is returned when a rotation was based on a bundle
// version that is no longer current.
type ErrBundleVersionMismatch struct {
	CurrentVersion int
}

func (err *ErrBundleVersionMismatch) Error() string {
	return fmt.Sprintf("key bundle version mismatch: current is %d", err.CurrentVersion)
}

// KeyBundle is an account's wrapped key material. Every value is opaque to the
// server and stored verbatim.
type KeyBundle struct {
	UserID          string `json:"userId"`
	Version         int    `json:"version"`
	PwhashSalt      string `json:"pwhashSalt,omitempty"`
	PwhashOps       int    `json:"pwhashOps,omitempty"`
	PwhashMem       int    `json:"pwhashMem,omitempty"`
	AmkPassword     string `json:"amkPassword"`
	AmkRecovery     string `json:"amkRecovery"`
	IdentityPrivate string `json:"identityPrivate"`
	EncPub          string `json:"encPub"`
	SignPub         string `json:"signPub"`
	SelfSig         string `json:"selfSig"`
}

// PublicIdentity is the part of a bundle other users may look up.
type PublicIdentity struct {
	UserID  string `json:"userId"`
	EncPub  string `json:"encPub"`
	SignPub string `json:"signPub"`
	SelfSig string `json:"selfSig"`
	Version int    `json:"version"`
}

type dbKeyBundle struct {
	User            *models.RecordID `json:"user"`
	Version         int              `json:"version"`
	PwhashSalt      string           `json:"pwhash_salt"`
	PwhashOps       int              `json:"pwhash_ops"`
	PwhashMem       int              `json:"pwhash_mem"`
	AmkPassword     string           `json:"amk_password"`
	AmkRecovery     string           `json:"amk_recovery"`
	IdentityPrivate string           `json:"identity_private"`
	EncPub          string           `json:"enc_pub"`
	SignPub         string           `json:"sign_pub"`
	SelfSig         string           `json:"self_sig"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

func (row dbKeyBundle) toBundle() *KeyBundle {
	return &KeyBundle{
		UserID:          recordIDString(row.User),
		Version:         row.Version,
		PwhashSalt:      row.PwhashSalt,
		PwhashOps:       row.PwhashOps,
		PwhashMem:       row.PwhashMem,
		AmkPassword:     row.AmkPassword,
		AmkRecovery:     row.AmkRecovery,
		IdentityPrivate: row.IdentityPrivate,
		EncPub:          row.EncPub,
		SignPub:         row.SignPub,
		SelfSig:         row.SelfSig,
	}
}

func (s *SurrealStore) GetKeyBundle(ctx context.Context, userID string) (*KeyBundle, error) {
	row, err := queryFirst[dbKeyBundle](ctx, s.DB,
		"SELECT * FROM key_bundle WHERE user = $user LIMIT 1",
		map[string]any{"user": models.NewRecordID("user", userID)},
	)
	if err != nil {
		return nil, err
	}
	return row.toBundle(), nil
}

func (s *SurrealStore) GetPublicIdentityByUserID(ctx context.Context, userID string) (*PublicIdentity, error) {
	bundle, err := s.GetKeyBundle(ctx, userID)
	if err != nil {
		return nil, err
	}
	return bundle.publicIdentity(), nil
}

func (s *SurrealStore) GetPublicIdentityByEmail(ctx context.Context, email string) (*PublicIdentity, error) {
	user, err := s.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return s.GetPublicIdentityByUserID(ctx, recordIDString(user.ID))
}

func (bundle *KeyBundle) publicIdentity() *PublicIdentity {
	return &PublicIdentity{
		UserID:  bundle.UserID,
		EncPub:  bundle.EncPub,
		SignPub: bundle.SignPub,
		SelfSig: bundle.SelfSig,
		Version: bundle.Version,
	}
}

// txOutcome is the status object a transaction returns to report why it did or
// did not write.
type txOutcome struct {
	Status  string `json:"status"`
	Version int    `json:"version"`
}

// RotateKeyBundle swaps the user's bundle for next if expectedVersion is still
// current. next.Version must be expectedVersion+1. When authKey is non-nil the
// account's auth hash changes in the same transaction (password change). The
// KDF parameters are left as they are when next carries none.
func (s *SurrealStore) RotateKeyBundle(ctx context.Context, userID string, expectedVersion int, next KeyBundle, authKey *string) error {
	if next.Version != expectedVersion+1 {
		return fmt.Errorf("rotation must carry version %d, got %d", expectedVersion+1, next.Version)
	}
	statement, params, err := rotationStatement(userID, expectedVersion, next, authKey)
	if err != nil {
		return err
	}
	outcome, err := queryReturned[txOutcome](ctx, s.DB, statement, params)
	if err != nil {
		return fmt.Errorf("rotate key bundle: %w", err)
	}
	return outcomeError(outcome)
}

func outcomeError(outcome *txOutcome) error {
	switch outcome.Status {
	case "ok":
		return nil
	case "conflict":
		return &ErrBundleVersionMismatch{CurrentVersion: outcome.Version}
	default:
		return ErrNotFound
	}
}

func rotationStatement(userID string, expectedVersion int, next KeyBundle, authKey *string) (string, map[string]any, error) {
	assignments, params := rotationAssignments(userID, expectedVersion, next)
	authUpdate := ""
	if authKey != nil {
		hash, err := bcrypt.GenerateFromPassword([]byte(*authKey), bcrypt.DefaultCost)
		if err != nil {
			return "", nil, fmt.Errorf("hash auth key: %w", err)
		}
		authUpdate = "UPDATE $user SET auth_hash = $auth_hash;"
		params["auth_hash"] = string(hash)
	}

	statement := `
		BEGIN TRANSACTION;
		LET $current = (SELECT * FROM ONLY key_bundle WHERE user = $user);
		LET $outcome = IF $current = NONE {
			{ status: 'missing', version: 0 }
		} ELSE IF $current.version != $expected_version {
			{ status: 'conflict', version: $current.version }
		} ELSE {
			UPDATE key_bundle SET ` + strings.Join(assignments, ", ") + ` WHERE user = $user;
			` + authUpdate + `
			{ status: 'ok', version: $next_version }
		};
		RETURN $outcome;
		COMMIT TRANSACTION;`
	return statement, params, nil
}

// rotationAssignments lists the key_bundle assignments of a rotation with their
// parameters. The KDF parameters change only when the new bundle carries them.
func rotationAssignments(userID string, expectedVersion int, next KeyBundle) ([]string, map[string]any) {
	assignments := []string{
		"version = $next_version", "amk_password = $amk_password", "amk_recovery = $amk_recovery",
		"identity_private = $identity_private", "enc_pub = $enc_pub", "sign_pub = $sign_pub",
		"self_sig = $self_sig",
	}
	params := map[string]any{
		"user":             models.NewRecordID("user", userID),
		"expected_version": expectedVersion,
		"next_version":     next.Version,
		"amk_password":     next.AmkPassword,
		"amk_recovery":     next.AmkRecovery,
		"identity_private": next.IdentityPrivate,
		"enc_pub":          next.EncPub,
		"sign_pub":         next.SignPub,
		"self_sig":         next.SelfSig,
	}
	if next.PwhashSalt != "" {
		assignments = append(assignments, "pwhash_salt = $pwhash_salt", "pwhash_ops = $pwhash_ops", "pwhash_mem = $pwhash_mem")
		params["pwhash_salt"] = next.PwhashSalt
		params["pwhash_ops"] = next.PwhashOps
		params["pwhash_mem"] = next.PwhashMem
	}
	return assignments, params
}
