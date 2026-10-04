package database

import (
	"context"
	"errors"
	"time"

	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// IdentityKey is one version of a user's identity key pair. Version 1 has no
// RotationSig; every later version carries the previous version's signature
// over its public keys.
type IdentityKey struct {
	UserID      string     `json:"userId"`
	Version     int        `json:"version"`
	SignPub     string     `json:"signPub"`
	EncPub      string     `json:"encPub"`
	RotationSig string     `json:"rotationSig,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	RetiredAt   *time.Time `json:"retiredAt"`
}

type dbIdentityKey struct {
	User        *models.RecordID `json:"user"`
	Version     int              `json:"version"`
	SignPub     string           `json:"sign_pub"`
	EncPub      string           `json:"enc_pub"`
	RotationSig *string          `json:"rotation_sig"`
	CreatedAt   time.Time        `json:"created_at"`
	RetiredAt   *time.Time       `json:"retired_at"`
}

func (row dbIdentityKey) toIdentityKey() IdentityKey {
	key := IdentityKey{
		UserID:    recordIDString(row.User),
		Version:   row.Version,
		SignPub:   row.SignPub,
		EncPub:    row.EncPub,
		CreatedAt: row.CreatedAt,
		RetiredAt: row.RetiredAt,
	}
	if row.RotationSig != nil {
		key.RotationSig = *row.RotationSig
	}
	return key
}

// GetIdentityKeys returns every identity version of the user, oldest first.
func (s *SurrealStore) GetIdentityKeys(ctx context.Context, userID string) ([]IdentityKey, error) {
	rows, err := queryRows[dbIdentityKey](ctx, s.DB,
		"SELECT * FROM identity_key WHERE user = $user ORDER BY version ASC",
		map[string]any{"user": models.NewRecordID("user", userID)})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	keys := make([]IdentityKey, 0, len(rows))
	for _, row := range rows {
		keys = append(keys, row.toIdentityKey())
	}
	return keys, nil
}

// verifyUnderIdentityHistory runs verify with each identity key, newest first,
// and returns the first result that verifies. A key that has been retired only
// counts for objects issued at or before its retiredAt.
func verifyUnderIdentityHistory[Verified any](keys []IdentityKey, issuedAt func(*Verified) time.Time, verify func(signPub string) (*Verified, error)) (*Verified, error) {
	var lastErr error = errors.New("the user has no identity keys")
	for index := len(keys) - 1; index >= 0; index-- {
		verified, err := verify(keys[index].SignPub)
		if err != nil {
			lastErr = err
			continue
		}
		retiredAt := keys[index].RetiredAt
		if retiredAt != nil && issuedAt(verified).After(*retiredAt) {
			lastErr = errors.New("signed by an identity key that was already retired")
			continue
		}
		return verified, nil
	}
	return nil, lastErr
}
