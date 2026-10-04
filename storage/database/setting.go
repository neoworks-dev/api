package database

import (
	"context"
	"fmt"
	"time"

	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// Setting is one per-user key/value pair owned by a client. The value is a JSON
// string the client encodes; settings are plaintext, not end-to-end encrypted.
type Setting struct {
	ClientID  string    `json:"clientId"`
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type dbSetting struct {
	ClientID  string    `json:"client_id"`
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (row dbSetting) toSetting() Setting {
	return Setting{ClientID: row.ClientID, Key: row.Key, Value: row.Value, UpdatedAt: row.UpdatedAt}
}

// SetSetting writes the value for (client, user, key), replacing any existing one.
func (s *SurrealStore) SetSetting(ctx context.Context, userID, clientID, key, value string) (*Setting, error) {
	rows, err := queryReturned[[]dbSetting](ctx, s.DB, `
		BEGIN TRANSACTION;
		LET $existing = (SELECT VALUE id FROM ONLY setting
			WHERE user = $user AND client_id = $client AND key = $key);
		LET $row = IF $existing = NONE {
			(CREATE setting SET user = $user, client_id = $client, key = $key, value = $value)[0]
		} ELSE {
			(UPDATE $existing SET value = $value)[0]
		};
		RETURN [$row];
		COMMIT TRANSACTION;`,
		settingParams(userID, clientID, key, value))
	if err != nil {
		return nil, fmt.Errorf("set setting: %w", err)
	}
	if len(*rows) == 0 {
		return nil, fmt.Errorf("set setting: no result returned")
	}
	setting := (*rows)[0].toSetting()
	return &setting, nil
}

func (s *SurrealStore) GetSetting(ctx context.Context, userID, clientID, key string) (*Setting, error) {
	row, err := queryFirst[dbSetting](ctx, s.DB,
		"SELECT * FROM setting WHERE user = $user AND client_id = $client AND key = $key LIMIT 1",
		settingParams(userID, clientID, key, ""))
	if err != nil {
		return nil, err
	}
	setting := row.toSetting()
	return &setting, nil
}

// ListSettings returns the user's settings, optionally limited to one client.
func (s *SurrealStore) ListSettings(ctx context.Context, userID, clientID string) ([]Setting, error) {
	query := "SELECT * FROM setting WHERE user = $user ORDER BY key ASC"
	params := map[string]any{"user": models.NewRecordID("user", userID)}
	if clientID != "" {
		query = "SELECT * FROM setting WHERE user = $user AND client_id = $client ORDER BY key ASC"
		params["client"] = clientID
	}
	rows, err := queryRows[dbSetting](ctx, s.DB, query, params)
	if err != nil {
		return nil, fmt.Errorf("list settings: %w", err)
	}
	settings := make([]Setting, 0, len(rows))
	for _, row := range rows {
		settings = append(settings, row.toSetting())
	}
	return settings, nil
}

func (s *SurrealStore) DeleteSetting(ctx context.Context, userID, clientID, key string) error {
	return queryExec(ctx, s.DB,
		"DELETE setting WHERE user = $user AND client_id = $client AND key = $key",
		settingParams(userID, clientID, key, ""))
}

func settingParams(userID, clientID, key, value string) map[string]any {
	return map[string]any{
		"user":   models.NewRecordID("user", userID),
		"client": clientID,
		"key":    key,
		"value":  value,
	}
}
