package database

import (
	"context"
	"fmt"
	"time"

	gql_model "github.com/neoworks/auth/gql/model"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

type SettingStore struct {
	DB *surrealdb.DB
}

type dbSetting struct {
	ClientID  string    `json:"client_id"`
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

func settingToGQL(s *dbSetting) *gql_model.Setting {
	return &gql_model.Setting{
		ClientID:  s.ClientID,
		Key:       s.Key,
		Value:     s.Value,
		UpdatedAt: s.UpdatedAt.Format(time.RFC3339),
	}
}

func firstSetting(results *[]surrealdb.QueryResult[[]dbSetting]) *gql_model.Setting {
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return settingToGQL(&qr.Result[0])
		}
	}
	return nil
}

// Set upserts a setting for (clientID, user, key). The unique index guarantees a
// single row per triple, so an existing one is replaced.
func (store *SettingStore) Set(ctx context.Context, clientID string, user models.RecordID, key, value string) (*gql_model.Setting, error) {
	params := map[string]any{"client": clientID, "user": user, "key": key, "value": value}
	if _, err := surrealdb.Query[[]any](ctx, store.DB,
		"DELETE setting WHERE user = $user AND client_id = $client AND key = $key",
		params,
	); err != nil {
		return nil, fmt.Errorf("set setting: %w", err)
	}
	results, err := surrealdb.Query[[]dbSetting](ctx, store.DB,
		"CREATE setting SET user = $user, client_id = $client, key = $key, value = $value RETURN AFTER",
		params,
	)
	if err != nil {
		return nil, fmt.Errorf("set setting: %w", err)
	}
	if s := firstSetting(results); s != nil {
		return s, nil
	}
	return nil, fmt.Errorf("set setting: no result returned")
}

// Get returns a single setting for (clientID, user, key), or nil if absent.
func (store *SettingStore) Get(ctx context.Context, user models.RecordID, clientID, key string) (*gql_model.Setting, error) {
	results, err := surrealdb.Query[[]dbSetting](ctx, store.DB,
		"SELECT * FROM setting WHERE user = $user AND client_id = $client AND key = $key LIMIT 1",
		map[string]any{"user": user, "client": clientID, "key": key},
	)
	if err != nil {
		return nil, fmt.Errorf("get setting: %w", err)
	}
	return firstSetting(results), nil
}

// List returns the user's settings, optionally scoped to a single client.
func (store *SettingStore) List(ctx context.Context, user models.RecordID, clientID *string) ([]*gql_model.Setting, error) {
	query := "SELECT * FROM setting WHERE user = $user"
	params := map[string]any{"user": user}
	if clientID != nil {
		query += " AND client_id = $client"
		params["client"] = *clientID
	}
	query += " ORDER BY key ASC"
	results, err := surrealdb.Query[[]dbSetting](ctx, store.DB, query, params)
	if err != nil {
		return nil, fmt.Errorf("list settings: %w", err)
	}
	for _, qr := range *results {
		out := make([]*gql_model.Setting, len(qr.Result))
		for i := range qr.Result {
			out[i] = settingToGQL(&qr.Result[i])
		}
		return out, nil
	}
	return nil, nil
}

// Delete removes a setting for (clientID, user, key).
func (store *SettingStore) Delete(ctx context.Context, clientID string, user models.RecordID, key string) error {
	_, err := surrealdb.Query[[]any](ctx, store.DB,
		"DELETE setting WHERE user = $user AND client_id = $client AND key = $key",
		map[string]any{"user": user, "client": clientID, "key": key},
	)
	return err
}
