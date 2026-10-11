package database

import "context"

// ClientStanding is what decides how a client is treated on every request: its
// rate limit multiplier and whether it is suspended.
type ClientStanding struct {
	FirstParty   bool     `json:"first_party"`
	Verified     bool     `json:"verified"`
	ReviewStatus string   `json:"review_status"`
	Multiplier   *float64 `json:"rate_limit_multiplier"`
}

// Suspended reports whether Neoworks suspended the client.
func (standing ClientStanding) Suspended() bool {
	return standing.ReviewStatus == ReviewStatusSuspended
}

// GetClientStanding returns the standing of the client; ErrNotFound when it does
// not exist.
func (s *SurrealStore) GetClientStanding(ctx context.Context, clientID string) (*ClientStanding, error) {
	return queryFirst[ClientStanding](ctx, s.DB,
		"SELECT first_party, verified, review_status, rate_limit_multiplier FROM $client",
		map[string]any{"client": clientRecord(clientID)})
}
