package gql

import (
	"context"
	"fmt"
	"time"

	gql_model "github.com/neoworks/auth/gql/model"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

type dbNotification struct {
	ID        *models.RecordID `json:"id,omitempty"`
	Title     string           `json:"title"`
	Body      string           `json:"body"`
	URL       *string          `json:"url,omitempty"`
	Read      bool             `json:"read"`
	CreatedAt time.Time        `json:"created_at"`
}

func notificationToGQL(n *dbNotification) *gql_model.Notification {
	id := ""
	if n.ID != nil {
		id = fmt.Sprintf("%v", n.ID.ID)
	}
	return &gql_model.Notification{
		ID:        id,
		Title:     n.Title,
		Body:      n.Body,
		URL:       n.URL,
		Read:      n.Read,
		CreatedAt: n.CreatedAt.String(),
	}
}

func firstNotification(results *[]surrealdb.QueryResult[[]dbNotification]) *dbNotification {
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			n := qr.Result[0]
			return &n
		}
	}
	return nil
}

// notify creates a notification for a user and pushes it to their devices. Unlike
// the SendNotification mutation it performs no scope check — it is for
// system-originated notifications (e.g. event invites). Delivery is best-effort.
func (r *mutationResolver) notify(ctx context.Context, userID, title, body string, url *string) (*dbNotification, error) {
	results, err := surrealdb.Query[[]dbNotification](ctx, r.store.DB, `
		CREATE notification SET
			user  = $user,
			title = $title,
			body  = $body,
			url   = $url
		RETURN AFTER
	`, map[string]any{
		"user":  models.NewRecordID("user", userID),
		"title": title,
		"body":  body,
		"url":   url,
	})
	if err != nil {
		return nil, fmt.Errorf("create notification: %w", err)
	}
	notification := firstNotification(results)
	if notification == nil {
		return nil, fmt.Errorf("create notification: no result")
	}
	r.deliverNotification(ctx, userID, notification)
	return notification, nil
}

// deliverNotification pushes the notification to the user's authenticator devices.
// Delivery is best-effort: a push failure never fails the calling mutation.
func (r *mutationResolver) deliverNotification(ctx context.Context, userID string, n *dbNotification) {
	tokens, err := r.store.ListPushTokensForUser(ctx, userID)
	if err != nil || len(tokens) == 0 {
		return
	}
	data := map[string]string{"type": "notification"}
	if n.ID != nil {
		data["notification_id"] = fmt.Sprintf("%v", n.ID.ID)
	}
	if n.URL != nil {
		data["url"] = *n.URL
	}
	_ = r.pusher.Send(ctx, tokens, n.Title, n.Body, data)
}
