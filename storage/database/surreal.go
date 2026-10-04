package database

import (
	"context"
	"errors"

	"github.com/neoworks/auth/oauth"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

var ErrNotFound = errors.New("not found")

type SurrealStore struct {
	DB *surrealdb.DB
}

func NewSurrealStore(url, user, pass, ns, dbName string) (*SurrealStore, error) {
	ctx := context.Background()

	db, err := surrealdb.FromEndpointURLString(ctx, url)
	if err != nil {
		return nil, err
	}

	if _, err := db.SignIn(ctx, surrealdb.Auth{
		Username: user,
		Password: pass,
	}); err != nil {
		return nil, err
	}

	if err := db.Use(ctx, ns, dbName); err != nil {
		return nil, err
	}

	return &SurrealStore{DB: db}, nil
}

// ── Clients ───────────────────────────────────────────────────────────────────

func (s *SurrealStore) GetClient(ctx context.Context, id string) (*oauth.Client, error) {
	results, err := surrealdb.Query[[]oauth.Client](
		ctx, s.DB,
		"SELECT * FROM client WHERE id = $id LIMIT 1",
		map[string]any{
			"id": models.NewRecordID("client", id),
		},
	)
	if err != nil {
		return nil, err
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, ErrNotFound
}

// -- Users -----------------------------------

func (s *SurrealStore) GetUserByID(ctx context.Context, id string) (*oauth.User, error) {
	results, err := surrealdb.Query[[]oauth.User](
		ctx, s.DB,
		"SELECT * FROM user WHERE id = $id LIMIT 1",
		map[string]any{"id": models.NewRecordID("user", id)},
	)
	if err != nil {
		return nil, err
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, ErrNotFound
}

func (s *SurrealStore) GetUserByEmail(ctx context.Context, email string) (*oauth.User, error) {
	results, err := surrealdb.Query[[]oauth.User](
		ctx, s.DB,
		"SELECT * FROM user WHERE email = $email LIMIT 1",
		map[string]any{"email": email},
	)
	if err != nil {
		return nil, err
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, ErrNotFound
}

// ── Refresh tokens ────────────────────────────────────────────────────────────

func (s *SurrealStore) SaveRefreshToken(ctx context.Context, rt oauth.RefreshToken) error {
	assignments := "id = $id, user = $user, client = $client, scopes = $scopes, " +
		"used = false, revoked = false, expires_at = $expires_at, created_at = $created_at"
	params := map[string]any{
		"id":         rt.ID,
		"user":       rt.User,
		"client":     rt.Client,
		"scopes":     rt.Scopes,
		"expires_at": rt.ExpiresAt,
		"created_at": rt.CreatedAt,
	}
	if rt.Install != nil {
		assignments += ", install = $install"
		params["install"] = rt.Install
	}
	_, err := surrealdb.Query[[]any](ctx, s.DB, "CREATE refresh_token SET "+assignments, params)
	return err
}

func (s *SurrealStore) GetRefreshToken(ctx context.Context, jti string) (*oauth.RefreshToken, error) {
	results, err := surrealdb.Query[[]oauth.RefreshToken](
		ctx, s.DB,
		"SELECT * FROM refresh_token WHERE id = $id LIMIT 1",
		map[string]any{"id": models.NewRecordID("refresh_token", jti)},
	)
	if err != nil {
		return nil, err
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, ErrNotFound
}

func (s *SurrealStore) MarkRefreshTokenUsed(ctx context.Context, jti string) error {
	_, err := surrealdb.Query[[]any](
		ctx, s.DB,
		"UPDATE refresh_token SET used = true WHERE id = $id",
		map[string]any{"id": models.NewRecordID("refresh_token", jti)},
	)
	return err
}

func (s *SurrealStore) RevokeRefreshToken(ctx context.Context, jti string) error {
	_, err := surrealdb.Query[[]any](
		ctx, s.DB,
		"UPDATE refresh_token SET revoked = true WHERE id = $id",
		map[string]any{"id": models.NewRecordID("refresh_token", jti)},
	)
	return err
}

func (s *SurrealStore) RevokeGrant(ctx context.Context, user, client *models.RecordID) error {
	_, err := surrealdb.Query[[]any](ctx, s.DB, `
        UPDATE refresh_token SET revoked = true
        WHERE user = $user AND client = $client
    `, map[string]any{
		"user":   user,
		"client": client,
	})
	return err
}

// ── Grants ────────────────────────────────────────────────────────────────────

func (s *SurrealStore) UpsertGrant(ctx context.Context, grant *oauth.Grant) error {
	_, err := surrealdb.Query[[]any](ctx, s.DB, `
        UPSERT grant SET
            user       = $user,
            client     = $client,
            scopes     = $scopes,
            enabled    = $enabled,
            updated_at = time::now()
        WHERE user = $user AND client = $client
    `, map[string]any{
		"user":    grant.User,
		"client":  grant.Client,
		"scopes":  grant.Scopes,
		"enabled": grant.Enabled,
	})
	return err
}

func (s *SurrealStore) GetGrant(ctx context.Context, user, client *models.RecordID) (*oauth.Grant, error) {
	results, err := surrealdb.Query[[]oauth.Grant](ctx, s.DB, `
        SELECT * FROM grant
        WHERE user = $user AND client = $client
        LIMIT 1
    `, map[string]any{
		"user":   user,
		"client": client,
	})
	if err != nil {
		return nil, err
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, ErrNotFound
}
