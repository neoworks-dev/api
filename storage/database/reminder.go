package database

import (
	"context"
	"fmt"
	"time"

	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// ReminderCandidate is a non-recurring event that carries reminder offsets and
// starts within the scheduler's look-ahead window.
type ReminderCandidate struct {
	ID        string
	Org       models.RecordID
	Title     string
	StartTime time.Time
	Reminders []int
}

type dbReminderCandidate struct {
	ID        *models.RecordID `json:"id,omitempty"`
	Org       *models.RecordID `json:"organization,omitempty"`
	Title     string           `json:"title"`
	StartTime time.Time        `json:"start_time"`
	Reminders []int            `json:"reminders"`
}

// ListReminderCandidates returns non-recurring events whose start_time falls in
// (fromStart, toStart] and that have at least one reminder offset. Recurring
// events are excluded — their reminders are not yet expanded server-side.
func (s *SurrealStore) ListReminderCandidates(ctx context.Context, fromStart, toStart time.Time) ([]ReminderCandidate, error) {
	results, err := surrealdb.Query[[]dbReminderCandidate](ctx, s.DB, `
		SELECT id, organization, title, start_time, reminders FROM event
		WHERE recurrence = NONE
		AND type::is_array(reminders)
		AND array::len(reminders) > 0
		AND start_time >  <datetime>$from
		AND start_time <= <datetime>$to
	`, map[string]any{"from": fromStart, "to": toStart})
	if err != nil {
		return nil, fmt.Errorf("list reminder candidates: %w", err)
	}

	var out []ReminderCandidate
	for _, qr := range *results {
		for i := range qr.Result {
			row := qr.Result[i]
			id := ""
			if row.ID != nil {
				id = fmt.Sprintf("%v", row.ID.ID)
			}
			var org models.RecordID
			if row.Org != nil {
				org = *row.Org
			}
			out = append(out, ReminderCandidate{
				ID:        id,
				Org:       org,
				Title:     row.Title,
				StartTime: row.StartTime,
				Reminders: row.Reminders,
			})
		}
	}
	return out, nil
}

// ListOrgMemberIDs returns the user-id strings of every member of an organization.
func (s *SurrealStore) ListOrgMemberIDs(ctx context.Context, orgRef models.RecordID) ([]string, error) {
	results, err := surrealdb.Query[[]models.RecordID](ctx, s.DB,
		"SELECT VALUE in FROM membership WHERE out = $org",
		map[string]any{"org": orgRef},
	)
	if err != nil {
		return nil, fmt.Errorf("list org members: %w", err)
	}
	var out []string
	for _, qr := range *results {
		for _, rec := range qr.Result {
			out = append(out, fmt.Sprintf("%v", rec.ID))
		}
	}
	return out, nil
}

// CreateNotification inserts a notification row for a user and returns its id.
func (s *SurrealStore) CreateNotification(ctx context.Context, userID, title, body string, url *string) (string, error) {
	results, err := surrealdb.Query[[]struct {
		ID *models.RecordID `json:"id,omitempty"`
	}](ctx, s.DB, `
		CREATE notification SET user = $user, title = $title, body = $body, url = $url RETURN AFTER
	`, map[string]any{
		"user":  models.NewRecordID("user", userID),
		"title": title,
		"body":  body,
		"url":   url,
	})
	if err != nil {
		return "", fmt.Errorf("create notification: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 && qr.Result[0].ID != nil {
			return fmt.Sprintf("%v", qr.Result[0].ID.ID), nil
		}
	}
	return "", nil
}
