package database

import (
	"context"
	"fmt"
	"time"

	"github.com/surrealdb/surrealdb.go/pkg/models"
)

type Notification struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	URL       *string   `json:"url"`
	Read      bool      `json:"read"`
	CreatedAt time.Time `json:"createdAt"`
}

type dbNotification struct {
	ID        *models.RecordID `json:"id"`
	Title     string           `json:"title"`
	Body      string           `json:"body"`
	URL       *string          `json:"url"`
	Read      bool             `json:"read"`
	CreatedAt time.Time        `json:"created_at"`
}

func (row dbNotification) toNotification() Notification {
	return Notification{
		ID:        recordIDString(row.ID),
		Title:     row.Title,
		Body:      row.Body,
		URL:       row.URL,
		Read:      row.Read,
		CreatedAt: row.CreatedAt,
	}
}

type CreateNotificationParams struct {
	UserID string
	Title  string
	Body   string
	URL    *string
}

func (s *SurrealStore) CreateNotification(ctx context.Context, params CreateNotificationParams) (*Notification, error) {
	assignments := "user = $user, title = $title, body = $body"
	queryParams := map[string]any{
		"user":  models.NewRecordID("user", params.UserID),
		"title": params.Title,
		"body":  params.Body,
	}
	if params.URL != nil {
		assignments += ", url = $url"
		queryParams["url"] = *params.URL
	}
	row, err := queryFirst[dbNotification](ctx, s.DB, "CREATE notification SET "+assignments, queryParams)
	if err != nil {
		return nil, fmt.Errorf("create notification: %w", err)
	}
	notification := row.toNotification()
	return &notification, nil
}

// ListNotifications returns the user's notifications, newest first.
func (s *SurrealStore) ListNotifications(ctx context.Context, userID string) ([]Notification, error) {
	rows, err := queryRows[dbNotification](ctx, s.DB,
		"SELECT * FROM notification WHERE user = $user ORDER BY created_at DESC",
		map[string]any{"user": models.NewRecordID("user", userID)})
	if err != nil {
		return nil, fmt.Errorf("list notifications: %w", err)
	}
	notifications := make([]Notification, 0, len(rows))
	for _, row := range rows {
		notifications = append(notifications, row.toNotification())
	}
	return notifications, nil
}

// MarkNotificationRead marks one of the user's notifications read; another
// user's notification is ErrNotFound.
func (s *SurrealStore) MarkNotificationRead(ctx context.Context, userID, notificationID string) error {
	_, err := queryFirst[dbNotification](ctx, s.DB,
		"UPDATE notification SET read = true WHERE id = $notification AND user = $user",
		map[string]any{
			"notification": models.NewRecordID("notification", notificationID),
			"user":         models.NewRecordID("user", userID),
		})
	return err
}
