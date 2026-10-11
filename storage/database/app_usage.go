package database

import (
	"context"
	"fmt"
	"time"
)

// InstallSpan is how long an install of an app was active. Nothing identifies
// the user or the device: usage is reported in aggregate only.
type InstallSpan struct {
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at"`
}

// UsageSnapshot holds the dates behind an app's usage numbers, with nothing
// that identifies a user.
type UsageSnapshot struct {
	// AuthorizedAt is when each user that currently holds an authorization
	// first authorized the app.
	AuthorizedAt []time.Time
	Installs     []InstallSpan
	// StorageBytes is what the app stores across all accounts.
	StorageBytes int64
}

type dbAuthorizedAt struct {
	CreatedAt time.Time `json:"created_at"`
}

// AppUsageSnapshot gathers the aggregate facts about an app's users.
func (s *SurrealStore) AppUsageSnapshot(ctx context.Context, clientID string) (*UsageSnapshot, error) {
	params := map[string]any{"client": clientRecord(clientID)}
	grants, err := queryRows[dbAuthorizedAt](ctx, s.DB,
		"SELECT created_at FROM grant WHERE client = $client AND enabled = true", params)
	if err != nil {
		return nil, fmt.Errorf("authorized users: %w", err)
	}
	installs, err := queryRows[InstallSpan](ctx, s.DB, "SELECT created_at, revoked_at FROM install WHERE client = $client", params)
	if err != nil {
		return nil, fmt.Errorf("installs: %w", err)
	}
	totals, err := queryRows[int64](ctx, s.DB,
		"SELECT VALUE math::sum(stored_bytes) FROM node WHERE client_id = $client_id GROUP ALL",
		map[string]any{"client_id": clientID})
	if err != nil {
		return nil, fmt.Errorf("app storage: %w", err)
	}
	snapshot := &UsageSnapshot{Installs: installs}
	for _, grant := range grants {
		snapshot.AuthorizedAt = append(snapshot.AuthorizedAt, grant.CreatedAt)
	}
	if len(totals) > 0 {
		snapshot.StorageBytes = totals[0]
	}
	return snapshot, nil
}
