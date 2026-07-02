package database

import (
	"context"
	"fmt"

	"github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// SignedPrekey is a device's current signed prekey: an X25519 public key signed by
// the device's Ed25519 identity so a sender can verify it before running X3DH.
type SignedPrekey struct {
	KeyID     int    `json:"key_id"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

// OneTimePrekey is one consumable X25519 public key from a device's pool.
type OneTimePrekey struct {
	KeyID     int    `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// DeviceBundle is the X3DH material a sender needs to start a session with one
// recipient device. OneTimePrekey is nil when the device's pool is exhausted.
type DeviceBundle struct {
	DeviceID      string         `json:"device_id"`
	IdentityKey   string         `json:"identity_key"`
	SigningKey    string         `json:"signing_key"`
	SignedPrekey  *SignedPrekey  `json:"signed_prekey"`
	OneTimePrekey *OneTimePrekey `json:"one_time_prekey,omitempty"`
}

// SetDeviceChatIdentity publishes a device's long-term chat identity keys. The
// device is addressed by (user, device_public_key) — the same handle a returning
// browser uses to fetch its wrapped AMK. Idempotent re-publish.
func (s *SurrealStore) SetDeviceChatIdentity(ctx context.Context, userID, devicePublicKey, identityKey, signingKey string) error {
	_, err := surrealdb.Query[[]any](ctx, s.DB,
		"UPDATE device SET identity_key = $identity_key, signing_key = $signing_key WHERE user = $user AND public_key = $device_public_key",
		map[string]any{
			"user":              models.NewRecordID("user", userID),
			"device_public_key": devicePublicKey,
			"identity_key":      identityKey,
			"signing_key":       signingKey,
		},
	)
	if err != nil {
		return fmt.Errorf("set device chat identity: %w", err)
	}
	return nil
}

// PublishSignedPrekey replaces the device's current signed prekey in one
// transaction, so a fetch never sees two competing signed prekeys.
func (s *SurrealStore) PublishSignedPrekey(ctx context.Context, deviceID string, prekey SignedPrekey) error {
	_, err := surrealdb.Query[[]any](ctx, s.DB, `
		BEGIN TRANSACTION;
		DELETE chat_signed_prekey WHERE device = $device;
		CREATE chat_signed_prekey SET device = $device, key_id = $key_id, public_key = $public_key, signature = $signature;
		COMMIT TRANSACTION;
	`, map[string]any{
		"device":     models.NewRecordID("device", deviceID),
		"key_id":     prekey.KeyID,
		"public_key": prekey.PublicKey,
		"signature":  prekey.Signature,
	})
	if err != nil {
		return fmt.Errorf("publish signed prekey: %w", err)
	}
	return nil
}

// AddOneTimePrekeys appends a batch of one-time prekeys to a device's pool.
func (s *SurrealStore) AddOneTimePrekeys(ctx context.Context, deviceID string, prekeys []OneTimePrekey) error {
	if len(prekeys) == 0 {
		return nil
	}
	items := make([]map[string]any, len(prekeys))
	for i, pk := range prekeys {
		items[i] = map[string]any{"key_id": pk.KeyID, "public_key": pk.PublicKey}
	}
	_, err := surrealdb.Query[[]any](ctx, s.DB, `
		FOR $pk IN $prekeys {
			CREATE chat_onetime_prekey SET device = $device, key_id = $pk.key_id, public_key = $pk.public_key;
		};
	`, map[string]any{
		"device":   models.NewRecordID("device", deviceID),
		"prekeys":  items,
	})
	if err != nil {
		return fmt.Errorf("add one-time prekeys: %w", err)
	}
	return nil
}

// CountOneTimePrekeys reports how many unused one-time prekeys remain for a device,
// so the client can replenish below a low-watermark.
func (s *SurrealStore) CountOneTimePrekeys(ctx context.Context, deviceID string) (int, error) {
	results, err := surrealdb.Query[[]struct {
		Count int `json:"count"`
	}](ctx, s.DB,
		"SELECT count() AS count FROM chat_onetime_prekey WHERE device = $device GROUP ALL",
		map[string]any{"device": models.NewRecordID("device", deviceID)},
	)
	if err != nil {
		return 0, fmt.Errorf("count one-time prekeys: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0].Count, nil
		}
	}
	return 0, nil
}

// GetPrekeyBundles returns one X3DH bundle per device of the target user that has
// published a chat identity. For each device it pops exactly one one-time prekey
// (atomic DELETE-RETURN in a transaction); devices with an empty pool return a
// bundle without one.
func (s *SurrealStore) GetPrekeyBundles(ctx context.Context, userID string) ([]*DeviceBundle, error) {
	devices, err := s.listChatDevices(ctx, userID)
	if err != nil {
		return nil, err
	}

	bundles := make([]*DeviceBundle, 0, len(devices))
	for _, device := range devices {
		signedPrekey, err := s.getSignedPrekey(ctx, device.RecordID)
		if err != nil {
			return nil, err
		}
		// A device without a signed prekey cannot start a session — skip it.
		if signedPrekey == nil {
			continue
		}
		oneTime, err := s.popOneTimePrekey(ctx, device.RecordID)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, &DeviceBundle{
			DeviceID:      device.DeviceID,
			IdentityKey:   device.IdentityKey,
			SigningKey:    device.SigningKey,
			SignedPrekey:  signedPrekey,
			OneTimePrekey: oneTime,
		})
	}
	return bundles, nil
}

type chatDevice struct {
	DeviceID    string // device public key — the relay routing id
	RecordID    string // bare device record id — used to look up its prekeys
	IdentityKey string
	SigningKey  string
}

func (s *SurrealStore) listChatDevices(ctx context.Context, userID string) ([]chatDevice, error) {
	// device_id in a bundle is the device PUBLIC KEY, not the bare record id: the
	// relay routes envelopes by (user, device public key) and a recipient polls its
	// own stream with the same public key, so the two must agree.
	results, err := surrealdb.Query[[]struct {
		ID          *models.RecordID `json:"id"`
		PublicKey   string           `json:"public_key"`
		IdentityKey string           `json:"identity_key"`
		SigningKey  string           `json:"signing_key"`
	}](ctx, s.DB,
		"SELECT id, public_key, identity_key, signing_key FROM device WHERE user = $user AND identity_key != NONE",
		map[string]any{"user": models.NewRecordID("user", userID)},
	)
	if err != nil {
		return nil, fmt.Errorf("list chat devices: %w", err)
	}
	for _, qr := range *results {
		out := make([]chatDevice, 0, len(qr.Result))
		for _, row := range qr.Result {
			if row.ID == nil {
				continue
			}
			out = append(out, chatDevice{
				DeviceID:    row.PublicKey,
				RecordID:    fmt.Sprintf("%v", row.ID.ID),
				IdentityKey: row.IdentityKey,
				SigningKey:  row.SigningKey,
			})
		}
		return out, nil
	}
	return nil, nil
}

func (s *SurrealStore) getSignedPrekey(ctx context.Context, deviceID string) (*SignedPrekey, error) {
	results, err := surrealdb.Query[[]SignedPrekey](ctx, s.DB,
		"SELECT key_id, public_key, signature, created_at FROM chat_signed_prekey WHERE device = $device ORDER BY created_at DESC LIMIT 1",
		map[string]any{"device": models.NewRecordID("device", deviceID)},
	)
	if err != nil {
		return nil, fmt.Errorf("get signed prekey: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, nil
}

// popOneTimePrekey atomically removes and returns one prekey. The SELECT + DELETE
// run in a single transaction so a key is never handed to two concurrent senders.
func (s *SurrealStore) popOneTimePrekey(ctx context.Context, deviceID string) (*OneTimePrekey, error) {
	results, err := surrealdb.Query[[]OneTimePrekey](ctx, s.DB, `
		BEGIN TRANSACTION;
		LET $otpk = (SELECT key_id, public_key, id FROM chat_onetime_prekey WHERE device = $device LIMIT 1);
		DELETE chat_onetime_prekey WHERE id IN $otpk.id;
		RETURN $otpk;
		COMMIT TRANSACTION;
	`, map[string]any{"device": models.NewRecordID("device", deviceID)})
	if err != nil {
		return nil, fmt.Errorf("pop one-time prekey: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, nil
}
