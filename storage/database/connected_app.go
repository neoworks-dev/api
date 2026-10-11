package database

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// PublicApp is an app as the users of it see it: who is behind it, whether its
// domains are verified, where it stands in review and its logo. Owner is nil
// for the seeded sample app, which belongs to no one.
type PublicApp struct {
	ID           string  `json:"clientId"`
	Name         string  `json:"name"`
	Description  string  `json:"description"`
	Owner        *Owner  `json:"owner"`
	Verified     bool    `json:"verified"`
	FirstParty   bool    `json:"firstParty"`
	ReviewStatus string  `json:"reviewStatus"`
	ReviewReason *string `json:"reviewReason"`
	// LogoAssetID is the logo users may see: nil without one, or while it is held.
	LogoAssetID *string `json:"-"`
}

// GetPublicApp returns the app as its users see it; ErrNotFound when it does not exist.
func (s *SurrealStore) GetPublicApp(ctx context.Context, clientID string) (*PublicApp, error) {
	row, err := queryFirst[dbApp](ctx, s.DB, "SELECT * FROM $client", map[string]any{"client": clientRecord(clientID)})
	if err != nil {
		return nil, err
	}
	owner, err := s.appOwner(ctx, row.Owner)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return row.toPublicApp(owner), nil
}

func (row dbApp) toPublicApp(owner *Owner) *PublicApp {
	app := &PublicApp{
		ID: recordTail(row.ID), Name: row.displayName(), Description: row.Description, Owner: owner,
		Verified: row.Verified || row.FirstParty, FirstParty: row.FirstParty, ReviewStatus: row.ReviewStatus,
	}
	if app.Name == "" {
		app.Name = app.ID
	}
	if row.ReviewStatus == ReviewStatusSuspended {
		app.ReviewReason = row.ReviewReason
	}
	if !row.LogoHeld || row.ReviewStatus == ReviewStatusApproved || row.FirstParty {
		app.LogoAssetID = row.logoAssetID()
	}
	return app
}

// ConnectedApp is an app the user authorized, with the installs they made of it
// and what it stores in their account.
type ConnectedApp struct {
	App              *PublicApp
	Scopes           []string
	AuthorizedAt     time.Time
	LastAuthorizedAt time.Time
	Installs         []Install
	Storage          AppStorage
}

type dbConnectedGrant struct {
	ClientID  string    `json:"client_id"`
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ListConnectedApps returns the apps the user authorized, most recently
// authorized first.
func (s *SurrealStore) ListConnectedApps(ctx context.Context, userID string) ([]ConnectedApp, error) {
	grants, err := queryRows[dbConnectedGrant](ctx, s.DB,
		`SELECT record::id(client) AS client_id, scopes, created_at, updated_at FROM grant
		WHERE user = $user AND enabled = true ORDER BY updated_at DESC`,
		map[string]any{"user": userRecord(userID)})
	if err != nil {
		return nil, fmt.Errorf("list connected apps: %w", err)
	}
	usage, err := s.appStorage(ctx, userID, "")
	if err != nil {
		return nil, err
	}
	apps := make([]ConnectedApp, 0, len(grants))
	for _, grant := range grants {
		connected, err := s.connectedApp(ctx, userID, grant, usage)
		if err != nil {
			return nil, err
		}
		apps = append(apps, *connected)
	}
	return apps, nil
}

func (s *SurrealStore) connectedApp(ctx context.Context, userID string, grant dbConnectedGrant, usage []AppStorage) (*ConnectedApp, error) {
	app, err := s.GetPublicApp(ctx, grant.ClientID)
	if err != nil {
		return nil, err
	}
	installs, err := s.listClientInstalls(ctx, userID, grant.ClientID)
	if err != nil {
		return nil, err
	}
	storage := AppStorage{ClientID: grant.ClientID}
	for _, entry := range usage {
		if entry.ClientID == grant.ClientID {
			storage = entry
		}
	}
	return &ConnectedApp{
		App: app, Scopes: grant.Scopes, AuthorizedAt: grant.CreatedAt, LastAuthorizedAt: grant.UpdatedAt,
		Installs: installs, Storage: storage,
	}, nil
}

func (s *SurrealStore) listClientInstalls(ctx context.Context, userID string, clientID string) ([]Install, error) {
	rows, err := queryRows[dbInstall](ctx, s.DB,
		"SELECT * FROM install WHERE user = $user AND client = $client ORDER BY created_at ASC",
		map[string]any{"user": userRecord(userID), "client": clientRecord(clientID)})
	if err != nil {
		return nil, fmt.Errorf("list client installs: %w", err)
	}
	installs := make([]Install, 0, len(rows))
	for _, row := range rows {
		installs = append(installs, row.toInstall())
	}
	return installs, nil
}
