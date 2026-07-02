package oauth

import (
	"time"

	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// EmergencyContact is a guardian the owner has designated for social recovery.
type EmergencyContact struct {
	ID         *models.RecordID `json:"id,omitempty"`
	Owner      *models.RecordID `json:"owner"`
	Guardian   *models.RecordID `json:"guardian"`
	Email      string           `json:"email"`
	Label      *string          `json:"label,omitempty"`
	ShareIndex int              `json:"share_index"`
	CreatedAt  time.Time        `json:"created_at"`
}

// RecoveryShare is one guardian's Shamir share, sealed to a single guardian
// device's public key. A guardian with multiple devices has one row per device.
type RecoveryShare struct {
	ID              *models.RecordID `json:"id,omitempty"`
	Owner           *models.RecordID `json:"owner"`
	Guardian        *models.RecordID `json:"guardian"`
	ShareIndex      int              `json:"share_index"`
	DevicePublicKey string           `json:"device_public_key"`
	SealedShare     string           `json:"sealed_share"`
	CreatedAt       time.Time        `json:"created_at"`
}

// RecoverySession tracks an in-progress account recovery on a new device.
type RecoverySession struct {
	ID                  *models.RecordID `json:"id,omitempty"`
	Owner               *models.RecordID `json:"owner"`
	RecoveringPublicKey string           `json:"recovering_public_key"`
	Threshold           int              `json:"threshold"`
	Status              string           `json:"status"`
	CreatedAt           time.Time        `json:"created_at"`
	ExpiresAt           time.Time        `json:"expires_at"`
}

// RecoverySessionShare is a share a guardian submitted for a session, re-sealed
// to the session's recovering_public_key so only the new device can open it.
type RecoverySessionShare struct {
	ID          *models.RecordID `json:"id,omitempty"`
	Session     *models.RecordID `json:"session"`
	Guardian    *models.RecordID `json:"guardian"`
	ShareIndex  int              `json:"share_index"`
	SealedShare string           `json:"sealed_share"`
	CreatedAt   time.Time        `json:"created_at"`
}
