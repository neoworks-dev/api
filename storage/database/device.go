package database

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

const (
	DeviceKindBrowser       = "browser"
	DeviceKindAuthenticator = "authenticator"
	DeviceKindApp           = "app"
)

type Device struct {
	ID         string     `json:"id"`
	Name       *string    `json:"name"`
	Kind       string     `json:"kind"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastSeenAt time.Time  `json:"lastSeenAt"`
	RevokedAt  *time.Time `json:"revokedAt"`
}

type dbDevice struct {
	ID         *models.RecordID `json:"id"`
	Name       *string          `json:"name"`
	Kind       string           `json:"kind"`
	CreatedAt  time.Time        `json:"created_at"`
	LastSeenAt time.Time        `json:"last_seen_at"`
	RevokedAt  *time.Time       `json:"revoked_at"`
}

func (row dbDevice) toDevice() Device {
	return Device{
		ID:         recordIDString(row.ID),
		Name:       row.Name,
		Kind:       row.Kind,
		CreatedAt:  row.CreatedAt,
		LastSeenAt: row.LastSeenAt,
		RevokedAt:  row.RevokedAt,
	}
}

// RegisterDeviceParams describes a device to record. DeviceID is generated when empty.
type RegisterDeviceParams struct {
	DeviceID string
	Name     string
	Kind     string
}

func addDeviceParams(params map[string]any, device *RegisterDeviceParams) {
	deviceID := device.DeviceID
	if deviceID == "" {
		deviceID = uuid.NewString()
	}
	params["device_ref"] = models.NewRecordID("device", deviceID)
	params["device_name"] = device.Name
	params["device_kind"] = device.Kind
}

func (s *SurrealStore) RegisterDevice(ctx context.Context, userID string, device *RegisterDeviceParams) (*Device, error) {
	params := map[string]any{"user_ref": models.NewRecordID("user", userID)}
	addDeviceParams(params, device)
	row, err := queryFirst[dbDevice](ctx, s.DB,
		"CREATE $device_ref SET user = $user_ref, name = $device_name, kind = $device_kind", params)
	if err != nil {
		return nil, fmt.Errorf("register device: %w", err)
	}
	created := row.toDevice()
	return &created, nil
}

func (s *SurrealStore) ListDevices(ctx context.Context, userID string) ([]Device, error) {
	rows, err := queryRows[dbDevice](ctx, s.DB,
		"SELECT * FROM device WHERE user = $user ORDER BY created_at ASC",
		map[string]any{"user": models.NewRecordID("user", userID)})
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	devices := make([]Device, 0, len(rows))
	for _, row := range rows {
		devices = append(devices, row.toDevice())
	}
	return devices, nil
}

// TouchDevice records that the device was just used.
func (s *SurrealStore) TouchDevice(ctx context.Context, userID, deviceID string) error {
	return queryExec(ctx, s.DB,
		"UPDATE device SET last_seen_at = time::now() WHERE id = $device AND user = $user AND revoked_at = NONE",
		map[string]any{
			"device": models.NewRecordID("device", deviceID),
			"user":   models.NewRecordID("user", userID),
		})
}

// RevokeDevice marks the device revoked and drops its push registrations. It is
// idempotent and returns ErrNotFound for a device the user does not own.
func (s *SurrealStore) RevokeDevice(ctx context.Context, userID, deviceID string) error {
	outcome, err := queryReturned[txOutcome](ctx, s.DB, `
		BEGIN TRANSACTION;
		LET $current = (SELECT * FROM ONLY $device WHERE user = $user);
		LET $outcome = IF $current = NONE {
			{ status: 'missing', version: 0 }
		} ELSE {
			UPDATE $device SET revoked_at = time::now() WHERE revoked_at = NONE;
			DELETE push_token WHERE device = $device;
			{ status: 'ok', version: 0 }
		};
		RETURN $outcome;
		COMMIT TRANSACTION;`,
		map[string]any{
			"device": models.NewRecordID("device", deviceID),
			"user":   models.NewRecordID("user", userID),
		})
	if err != nil {
		return fmt.Errorf("revoke device: %w", err)
	}
	return outcomeError(outcome)
}
