package database

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// Exercises the Google link store against the dev SurrealDB. The handler tests
// in apps/oauth run on a fake, so this is the only place the SurrealQL itself is
// checked. Requires migration 058.

func cleanupGoogle(t *testing.T, root *surrealdb.DB, userID models.RecordID) {
	t.Helper()
	ctx := context.Background()
	t.Cleanup(func() {
		for _, table := range []string{"google_event_link", "google_calendar_link", "google_account"} {
			_, _ = surrealdb.Query[[]any](ctx, root,
				"DELETE "+table+" WHERE user = $u", map[string]any{"u": userID})
		}
	})
}

func googleTestStore(t *testing.T) (*SurrealStore, *surrealdb.DB, models.RecordID) {
	t.Helper()
	url, user, pass, ns := testEnv()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")

	owner := newSpaceTestUser(t, root, "google_owner_"+randSuffix())
	cleanupSpaces(t, root, owner)
	cleanupGoogle(t, root, owner)
	return store, root, owner
}

func TestGoogleAccountLinkAndRelink(t *testing.T) {
	store, _, owner := googleTestStore(t)
	ctx := context.Background()
	google := store.Google

	if _, err := google.Account(ctx, owner); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unlinked account error = %v, want ErrNotFound", err)
	}

	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	err := google.LinkAccount(ctx, owner, LinkGoogleAccountParams{
		GoogleSub:    "sub-1",
		Email:        "first@example.com",
		RefreshToken: "refresh-1",
		AccessToken:  "access-1",
		ExpiresAt:    expiry,
		Scopes:       []string{"openid", "email"},
	})
	if err != nil {
		t.Fatalf("link: %v", err)
	}

	account, err := google.Account(ctx, owner)
	if err != nil {
		t.Fatalf("account: %v", err)
	}
	if account.RefreshToken != "refresh-1" || account.AccessToken != "access-1" {
		t.Fatalf("tokens = %+v", account)
	}
	if account.Email != "first@example.com" || account.GoogleSub != "sub-1" {
		t.Fatalf("identity = %+v", account)
	}
	if account.ExpiresAt == nil || !account.ExpiresAt.Equal(expiry) {
		t.Fatalf("expires_at = %v, want %v", account.ExpiresAt, expiry)
	}

	// A re-link that returns no refresh token must keep the stored one, or the
	// account becomes unrefreshable.
	err = google.LinkAccount(ctx, owner, LinkGoogleAccountParams{
		GoogleSub: "sub-1",
		Email:     "second@example.com",
		Scopes:    []string{"openid", "email"},
	})
	if err != nil {
		t.Fatalf("relink: %v", err)
	}

	account, err = google.Account(ctx, owner)
	if err != nil {
		t.Fatalf("account after relink: %v", err)
	}
	if account.RefreshToken != "refresh-1" {
		t.Errorf("refresh token = %q, want the stored one to survive", account.RefreshToken)
	}
	if account.Email != "second@example.com" {
		t.Errorf("email = %q, want the new one", account.Email)
	}

	// Only one row per user: the UNIQUE index would have rejected a second CREATE.
	refreshed := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	if err := google.SetAccessToken(ctx, owner, "access-2", refreshed); err != nil {
		t.Fatalf("set access token: %v", err)
	}
	account, err = google.Account(ctx, owner)
	if err != nil {
		t.Fatalf("account after refresh: %v", err)
	}
	if account.AccessToken != "access-2" || !account.ExpiresAt.Equal(refreshed) {
		t.Errorf("refreshed token = %+v", account)
	}
}

// The refresh token is the one live third-party credential this server stores,
// so it must not sit in the row as plaintext when a key is configured.
func TestGoogleTokensAreSealedAtRest(t *testing.T) {
	store, root, owner := googleTestStore(t)
	ctx := context.Background()

	encryptor, err := NewEncryptor(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatalf("encryptor: %v", err)
	}
	store.Google.UseEncryptor(encryptor)

	err = store.Google.LinkAccount(ctx, owner, LinkGoogleAccountParams{
		GoogleSub:    "sub-sealed",
		RefreshToken: "super-secret-refresh",
		AccessToken:  "super-secret-access",
		ExpiresAt:    time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("link: %v", err)
	}

	rows, err := surrealdb.Query[[]dbGoogleAccount](ctx, root,
		"SELECT * FROM google_account WHERE user = $u LIMIT 1", map[string]any{"u": owner})
	if err != nil {
		t.Fatalf("raw read: %v", err)
	}
	stored := (*rows)[0].Result[0]
	if stored.RefreshToken == "super-secret-refresh" {
		t.Error("refresh token is stored in plaintext")
	}
	if stored.AccessToken == nil || *stored.AccessToken == "super-secret-access" {
		t.Error("access token is stored in plaintext")
	}

	account, err := store.Google.Account(ctx, owner)
	if err != nil {
		t.Fatalf("account: %v", err)
	}
	if account.RefreshToken != "super-secret-refresh" {
		t.Errorf("refresh token did not round-trip: %q", account.RefreshToken)
	}
}

func TestGoogleCalendarAndEventLinks(t *testing.T) {
	store, _, owner := googleTestStore(t)
	ctx := context.Background()
	google := store.Google

	space, err := store.Spaces.Create(ctx, owner, CreateSpaceParams{
		SpaceID:    newTestUUID(),
		Collection: "calendar", Kind: "personal", WrappedKey: "wrap", Signature: "sig",
	})
	if err != nil {
		t.Fatalf("create space: %v", err)
	}

	err = google.SaveCalendarLink(ctx, owner, SaveGoogleCalendarLinkParams{
		SpaceID:          space.Space.ID,
		GoogleCalendarID: "primary",
		AccessRole:       "owner",
		Enabled:          true,
	})
	if err != nil {
		t.Fatalf("save calendar link: %v", err)
	}

	links, err := google.CalendarLinks(ctx, owner)
	if err != nil {
		t.Fatalf("list calendar links: %v", err)
	}
	if len(links) != 1 || links[0].GoogleCalendarID != "primary" || links[0].SpaceID != space.Space.ID {
		t.Fatalf("calendar links = %+v", links)
	}
	if links[0].SyncToken != nil {
		t.Errorf("sync token = %v, want unset", links[0].SyncToken)
	}

	// Advancing the cursor is an update of the same row, not a second one.
	token := "sync-token-1"
	err = google.SaveCalendarLink(ctx, owner, SaveGoogleCalendarLinkParams{
		SpaceID:          space.Space.ID,
		GoogleCalendarID: "primary",
		AccessRole:       "owner",
		SyncToken:        &token,
		Enabled:          true,
	})
	if err != nil {
		t.Fatalf("advance cursor: %v", err)
	}
	links, _ = google.CalendarLinks(ctx, owner)
	if len(links) != 1 {
		t.Fatalf("calendar links = %+v, want one row", links)
	}
	if links[0].SyncToken == nil || *links[0].SyncToken != token {
		t.Fatalf("sync token = %v, want %q", links[0].SyncToken, token)
	}

	// A 410 from Google clears the cursor, which is an empty string here.
	cleared := ""
	err = google.SaveCalendarLink(ctx, owner, SaveGoogleCalendarLinkParams{
		SpaceID:          space.Space.ID,
		GoogleCalendarID: "primary",
		AccessRole:       "owner",
		SyncToken:        &cleared,
		Enabled:          true,
	})
	if err != nil {
		t.Fatalf("clear cursor: %v", err)
	}
	links, _ = google.CalendarLinks(ctx, owner)
	if links[0].SyncToken != nil {
		t.Errorf("sync token = %v, want cleared", links[0].SyncToken)
	}

	hash := "hash-1"
	err = google.SaveEventLinks(ctx, owner, []GoogleEventLink{
		{UID: "uid-1", GoogleCalendarID: "primary", GoogleEventID: "gev-1", ContentHash: &hash},
		{UID: "uid-2", GoogleCalendarID: "primary", GoogleEventID: "gev-2"},
		{UID: "uid-3", GoogleCalendarID: "other", GoogleEventID: "gev-3"},
	})
	if err != nil {
		t.Fatalf("save event links: %v", err)
	}

	eventLinks, err := google.EventLinks(ctx, owner, "primary")
	if err != nil {
		t.Fatalf("list event links: %v", err)
	}
	if len(eventLinks) != 2 {
		t.Fatalf("event links for primary = %+v, want 2", eventLinks)
	}
	if eventLinks[0].ContentHash == nil || *eventLinks[0].ContentHash != hash {
		t.Errorf("content hash = %v, want %q", eventLinks[0].ContentHash, hash)
	}
	// A link pushed but not yet hashed is a real state: it means "pushed, hash
	// unknown", and must not have been rejected by the option<string> column.
	if eventLinks[1].ContentHash != nil {
		t.Errorf("content hash = %v, want unset", eventLinks[1].ContentHash)
	}

	// Re-saving the same uid updates rather than duplicating.
	newHash := "hash-2"
	err = google.SaveEventLinks(ctx, owner, []GoogleEventLink{
		{UID: "uid-1", GoogleCalendarID: "primary", GoogleEventID: "gev-1", ContentHash: &newHash},
	})
	if err != nil {
		t.Fatalf("resave event link: %v", err)
	}
	eventLinks, _ = google.EventLinks(ctx, owner, "primary")
	if len(eventLinks) != 2 || *eventLinks[0].ContentHash != newHash {
		t.Fatalf("event links after resave = %+v", eventLinks)
	}

	if err := google.DeleteEventLink(ctx, owner, "uid-2"); err != nil {
		t.Fatalf("delete event link: %v", err)
	}
	eventLinks, _ = google.EventLinks(ctx, owner, "primary")
	if len(eventLinks) != 1 {
		t.Fatalf("event links after delete = %+v, want 1", eventLinks)
	}

	// Dropping a calendar drops the event links derived from it, so re-linking
	// starts from a clean full sync — and leaves other calendars alone.
	if err := google.DeleteCalendarLink(ctx, owner, "primary"); err != nil {
		t.Fatalf("delete calendar link: %v", err)
	}
	links, _ = google.CalendarLinks(ctx, owner)
	if len(links) != 0 {
		t.Errorf("calendar links = %+v, want none", links)
	}
	all, _ := google.EventLinks(ctx, owner, "")
	if len(all) != 1 || all[0].UID != "uid-3" {
		t.Errorf("event links = %+v, want only the other calendar's", all)
	}
}

func TestGoogleUnlinkDropsEverything(t *testing.T) {
	store, _, owner := googleTestStore(t)
	ctx := context.Background()
	google := store.Google

	space, err := store.Spaces.Create(ctx, owner, CreateSpaceParams{
		SpaceID:    newTestUUID(),
		Collection: "calendar", Kind: "personal", WrappedKey: "wrap", Signature: "sig",
	})
	if err != nil {
		t.Fatalf("create space: %v", err)
	}

	mustLink := func(err error, what string) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	mustLink(google.LinkAccount(ctx, owner, LinkGoogleAccountParams{
		GoogleSub: "sub-unlink", RefreshToken: "refresh", AccessToken: "access",
		ExpiresAt: time.Now().Add(time.Hour),
	}), "link account")
	mustLink(google.SaveCalendarLink(ctx, owner, SaveGoogleCalendarLinkParams{
		SpaceID: space.Space.ID, GoogleCalendarID: "primary", AccessRole: "owner", Enabled: true,
	}), "save calendar link")
	mustLink(google.SaveEventLinks(ctx, owner, []GoogleEventLink{
		{UID: "uid-1", GoogleCalendarID: "primary", GoogleEventID: "gev-1"},
	}), "save event links")

	if err := google.Unlink(ctx, owner); err != nil {
		t.Fatalf("unlink: %v", err)
	}

	if _, err := google.Account(ctx, owner); !errors.Is(err, ErrNotFound) {
		t.Errorf("account error = %v, want ErrNotFound", err)
	}
	if links, _ := google.CalendarLinks(ctx, owner); len(links) != 0 {
		t.Errorf("calendar links = %+v, want none", links)
	}
	if links, _ := google.EventLinks(ctx, owner, ""); len(links) != 0 {
		t.Errorf("event links = %+v, want none", links)
	}
}
