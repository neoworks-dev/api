package notifications_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/handlers/handlertest"
	"github.com/neoworks/auth/handlers/notifications"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
)

type recordingSender struct{ titles []string }

func (sender *recordingSender) Send(_ context.Context, _ []*oauth.PushToken, title, _ string, _ map[string]string) error {
	sender.titles = append(sender.titles, title)
	return nil
}

func TestNotificationFeed(t *testing.T) {
	store := dbtest.New(t)
	sender := &recordingSender{}
	handler := notifications.NewHandler(store, sender)
	router := handlertest.NewAuthenticated(func(router chi.Router) { handler.RegisterAuthenticated(router) })
	user := handlertest.CreateUser(t, store)
	other := handlertest.CreateUser(t, store)
	if err := store.UpsertPushToken(context.Background(), user.UserID, nil, "fcm", "token-1"); err != nil {
		t.Fatalf("push token: %v", err)
	}

	own := router.Do(t, user, "POST", "/api/v1/notifications", map[string]string{"title": "Hi", "body": "There"}, nil)
	if own.Code != http.StatusOK {
		t.Fatalf("send to self: %d %s", own.Code, own.Body.String())
	}
	var created database.Notification
	handlertest.Decode(t, own, &created)
	if len(sender.titles) != 1 || sender.titles[0] != "Hi" {
		t.Fatalf("push not delivered: %v", sender.titles)
	}

	toOther := map[string]string{"userId": other.UserID, "title": "T", "body": "B"}
	if denied := router.Do(t, user, "POST", "/api/v1/notifications", toOther, nil); denied.Code != http.StatusForbidden {
		t.Fatalf("send to another user without scope: got %d want 403", denied.Code)
	}
	privileged := access.Principal{UserID: user.UserID, Scopes: []string{"notification:write"}}
	if allowed := router.Do(t, privileged, "POST", "/api/v1/notifications", toOther, nil); allowed.Code != http.StatusOK {
		t.Fatalf("send with scope: got %d want 200", allowed.Code)
	}

	if foreign := router.Do(t, other, "POST", "/api/v1/notifications/"+created.ID+"/read", nil, nil); foreign.Code != http.StatusNotFound {
		t.Fatalf("marking another user's notification: got %d want 404", foreign.Code)
	}
	if read := router.Do(t, user, "POST", "/api/v1/notifications/"+created.ID+"/read", nil, nil); read.Code != http.StatusNoContent {
		t.Fatalf("mark read: %d", read.Code)
	}
	var feed struct {
		Notifications []database.Notification `json:"notifications"`
	}
	handlertest.Decode(t, router.Do(t, user, "GET", "/api/v1/notifications", nil, nil), &feed)
	if len(feed.Notifications) != 1 || !feed.Notifications[0].Read {
		t.Fatalf("feed: %+v", feed)
	}
}
