package database

import (
	"context"
	"errors"
	"fmt"

	"github.com/neoworks/auth/utils"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

const contactCodeAttempts = 5

type dbContactCode struct {
	User models.RecordID `json:"user"`
	Code string          `json:"code"`
}

// GetContactCode returns the user's code, creating one on first use.
func (s *SurrealStore) GetContactCode(ctx context.Context, userID string) (string, error) {
	row, err := queryFirst[dbContactCode](ctx, s.DB,
		"SELECT * FROM contact_code WHERE user = $user LIMIT 1",
		map[string]any{"user": models.NewRecordID("user", userID)},
	)
	if err == nil {
		return row.Code, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return "", err
	}
	code, createErr := s.writeContactCode(ctx, userID, "CREATE contact_code SET user = $user, code = $code")
	if createErr == nil {
		return code, nil
	}
	// A concurrent first read may have created the row between select and create.
	row, err = queryFirst[dbContactCode](ctx, s.DB,
		"SELECT * FROM contact_code WHERE user = $user LIMIT 1",
		map[string]any{"user": models.NewRecordID("user", userID)},
	)
	if err != nil {
		return "", createErr
	}
	return row.Code, nil
}

// RegenerateContactCode replaces the user's code; the old one stops resolving.
func (s *SurrealStore) RegenerateContactCode(ctx context.Context, userID string) (string, error) {
	if _, err := s.GetContactCode(ctx, userID); err != nil {
		return "", err
	}
	return s.writeContactCode(ctx, userID, "UPDATE contact_code SET code = $code WHERE user = $user")
}

// writeContactCode runs the statement with a fresh code, retrying on the
// (unlikely) collision with another user's code.
func (s *SurrealStore) writeContactCode(ctx context.Context, userID string, statement string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < contactCodeAttempts; attempt++ {
		code, err := utils.GenerateContactCode()
		if err != nil {
			return "", err
		}
		lastErr = queryExec(ctx, s.DB, statement, map[string]any{
			"user": models.NewRecordID("user", userID), "code": code,
		})
		if lastErr == nil {
			return code, nil
		}
	}
	return "", fmt.Errorf("write contact code: %w", lastErr)
}

// ResolveContactCode returns the public identity of the code's owner. The code
// must already be canonical.
func (s *SurrealStore) ResolveContactCode(ctx context.Context, code string) (*PublicIdentity, error) {
	row, err := queryFirst[dbContactCode](ctx, s.DB,
		"SELECT * FROM contact_code WHERE code = $code LIMIT 1",
		map[string]any{"code": code},
	)
	if err != nil {
		return nil, err
	}
	return s.GetPublicIdentityByUserID(ctx, recordIDString(&row.User))
}
