package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// GoogleStore holds the link between a neoworks account and a Google account,
// plus the coordination state the client-side calendar sync needs: which Google
// calendar mirrors which space, Google's pull cursor per calendar, and the
// uid → Google event id map with a content hash.
//
// The refresh token is a live third-party bearer credential, unlike every other
// secret this server stores (wrapped key material it cannot unwrap). It is
// sealed at rest when an Encryptor is installed — see UseEncryptor and
// sql/migrations/058_google_link.surql. Event content never reaches here: the
// sync loop runs inside the Vault, and only opaque ids and hashes are recorded.
type GoogleStore struct {
	DB  *surrealdb.DB
	enc *Encryptor
}

// UseEncryptor seals Google tokens at rest. Optional: without it tokens are
// stored verbatim, which is acceptable only for local development.
func (store *GoogleStore) UseEncryptor(enc *Encryptor) { store.enc = enc }

type GoogleAccount struct {
	GoogleSub    string
	Email        string
	RefreshToken string
	AccessToken  string
	ExpiresAt    *time.Time
	Scopes       []string
	LinkedAt     time.Time
}

type GoogleCalendarLink struct {
	SpaceID          string  `json:"space_id"`
	GoogleCalendarID string  `json:"google_calendar_id"`
	AccessRole       string  `json:"access_role"`
	SyncToken        *string `json:"sync_token"`
	Enabled          bool    `json:"enabled"`
}

type GoogleEventLink struct {
	UID              string  `json:"uid"`
	GoogleCalendarID string  `json:"google_calendar_id"`
	GoogleEventID    string  `json:"google_event_id"`
	ContentHash      *string `json:"content_hash"`
}

// ── DB row shapes ─────────────────────────────────────────────────────────────

type dbGoogleAccount struct {
	GoogleSub    string     `json:"google_sub"`
	Email        *string    `json:"email"`
	RefreshToken string     `json:"refresh_token"`
	AccessToken  *string    `json:"access_token"`
	ExpiresAt    *time.Time `json:"expires_at"`
	Scopes       []string   `json:"scopes"`
	LinkedAt     time.Time  `json:"linked_at"`
}

type dbGoogleCalendarLink struct {
	Space            *models.RecordID `json:"space"`
	GoogleCalendarID string           `json:"google_calendar_id"`
	AccessRole       string           `json:"access_role"`
	SyncToken        *string          `json:"sync_token"`
	Enabled          bool             `json:"enabled"`
}

type dbGoogleEventLink struct {
	UID              string  `json:"uid"`
	GoogleCalendarID string  `json:"google_calendar_id"`
	GoogleEventID    string  `json:"google_event_id"`
	ContentHash      *string `json:"content_hash"`
}

// ── Account ───────────────────────────────────────────────────────────────────

type LinkGoogleAccountParams struct {
	GoogleSub string
	Email     string
	// Empty on a re-consent that returned no new refresh token; the stored one
	// stays in place. Google issues a refresh token only on the first grant
	// unless the authorization request forces the consent screen.
	RefreshToken string
	AccessToken  string
	ExpiresAt    time.Time
	Scopes       []string
}

// LinkAccount upserts the user's Google account row. The UNIQUE index on `user`
// makes this the single row per account, so a re-link overwrites rather than
// accumulating.
func (store *GoogleStore) LinkAccount(ctx context.Context, user models.RecordID, p LinkGoogleAccountParams) error {
	assignments := []string{"google_sub = $google_sub", "scopes = $scopes"}
	params := map[string]any{
		"user":       user,
		"google_sub": p.GoogleSub,
		// array<string> rejects NULL, and a nil slice marshals to one.
		"scopes": append([]string{}, p.Scopes...),
	}
	if p.Email != "" {
		assignments = append(assignments, "email = $email")
		params["email"] = p.Email
	}
	if p.RefreshToken != "" {
		assignments = append(assignments, "refresh_token = $refresh_token")
		params["refresh_token"] = sealWith(store.enc, p.RefreshToken)
	}
	if p.AccessToken != "" {
		assignments = append(assignments, "access_token = $access_token")
		params["access_token"] = sealWith(store.enc, p.AccessToken)
	}
	if !p.ExpiresAt.IsZero() {
		assignments = append(assignments, "expires_at = $expires_at")
		params["expires_at"] = p.ExpiresAt
	}

	set := strings.Join(assignments, ", ")
	query := `
		BEGIN TRANSACTION;
		LET $existing = (SELECT * FROM google_account WHERE user = $user LIMIT 1)[0];
		IF $existing != NONE {
			UPDATE $existing.id SET ` + set + `;
		} ELSE {
			CREATE google_account SET user = $user, ` + set + `;
		};
		COMMIT TRANSACTION;`

	if _, err := surrealdb.Query[[]any](ctx, store.DB, query, params); err != nil {
		return fmt.Errorf("link google account: %w", err)
	}
	return nil
}

// Account returns the user's linked Google account with its tokens opened, or
// ErrNotFound when no account is linked.
func (store *GoogleStore) Account(ctx context.Context, user models.RecordID) (*GoogleAccount, error) {
	results, err := surrealdb.Query[[]dbGoogleAccount](ctx, store.DB,
		"SELECT * FROM google_account WHERE user = $user LIMIT 1",
		map[string]any{"user": user},
	)
	if err != nil {
		return nil, fmt.Errorf("get google account: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) == 0 {
			continue
		}
		return store.toAccount(qr.Result[0]), nil
	}
	return nil, ErrNotFound
}

func (store *GoogleStore) toAccount(row dbGoogleAccount) *GoogleAccount {
	account := &GoogleAccount{
		GoogleSub:    row.GoogleSub,
		RefreshToken: openWith(store.enc, row.RefreshToken),
		ExpiresAt:    row.ExpiresAt,
		Scopes:       row.Scopes,
		LinkedAt:     row.LinkedAt,
	}
	if row.Email != nil {
		account.Email = *row.Email
	}
	if row.AccessToken != nil {
		account.AccessToken = openWith(store.enc, *row.AccessToken)
	}
	return account
}

// SetAccessToken records a freshly refreshed Google access token so concurrent
// devices reuse it instead of each spending a refresh round-trip.
func (store *GoogleStore) SetAccessToken(ctx context.Context, user models.RecordID, token string, expiresAt time.Time) error {
	_, err := surrealdb.Query[[]any](ctx, store.DB,
		"UPDATE google_account SET access_token = $access_token, expires_at = $expires_at WHERE user = $user",
		map[string]any{
			"user":         user,
			"access_token": sealWith(store.enc, token),
			"expires_at":   expiresAt,
		},
	)
	if err != nil {
		return fmt.Errorf("set google access token: %w", err)
	}
	return nil
}

// Unlink drops the account and every piece of sync state derived from it. The
// caller revokes the grant at Google first; this is the local half.
func (store *GoogleStore) Unlink(ctx context.Context, user models.RecordID) error {
	_, err := surrealdb.Query[[]any](ctx, store.DB, `
		BEGIN TRANSACTION;
		DELETE google_event_link WHERE user = $user;
		DELETE google_calendar_link WHERE user = $user;
		DELETE google_account WHERE user = $user;
		COMMIT TRANSACTION;`,
		map[string]any{"user": user},
	)
	if err != nil {
		return fmt.Errorf("unlink google account: %w", err)
	}
	return nil
}

// ── Calendar links ────────────────────────────────────────────────────────────

// CalendarLinks returns every calendar the user has mirrored into a space.
func (store *GoogleStore) CalendarLinks(ctx context.Context, user models.RecordID) ([]GoogleCalendarLink, error) {
	results, err := surrealdb.Query[[]dbGoogleCalendarLink](ctx, store.DB,
		"SELECT * FROM google_calendar_link WHERE user = $user ORDER BY created_at ASC",
		map[string]any{"user": user},
	)
	if err != nil {
		return nil, fmt.Errorf("list google calendar links: %w", err)
	}
	out := []GoogleCalendarLink{}
	for _, qr := range *results {
		for _, row := range qr.Result {
			out = append(out, GoogleCalendarLink{
				SpaceID:          recordIDString(row.Space),
				GoogleCalendarID: row.GoogleCalendarID,
				AccessRole:       row.AccessRole,
				SyncToken:        row.SyncToken,
				Enabled:          row.Enabled,
			})
		}
	}
	return out, nil
}

type SaveGoogleCalendarLinkParams struct {
	SpaceID          string
	GoogleCalendarID string
	AccessRole       string
	// Nil leaves the stored cursor alone; a pointer to "" clears it, which is what
	// a 410 from Google means — the next pull must be a full resync.
	SyncToken *string
	Enabled   bool
}

// SaveCalendarLink upserts one calendar → space mapping. `space` and
// `google_calendar_id` are READONLY, so an existing row keeps its space: a
// calendar cannot be re-pointed at a different space without unlinking first.
func (store *GoogleStore) SaveCalendarLink(ctx context.Context, user models.RecordID, p SaveGoogleCalendarLinkParams) error {
	spaceUUID, err := parseUUID(p.SpaceID)
	if err != nil {
		return fmt.Errorf("space_id must be a uuid")
	}

	assignments := []string{"access_role = $access_role", "enabled = $enabled"}
	params := map[string]any{
		"user":        user,
		"space":       models.NewRecordID("space", spaceUUID),
		"calendar":    p.GoogleCalendarID,
		"access_role": p.AccessRole,
		"enabled":     p.Enabled,
	}
	if p.SyncToken != nil && *p.SyncToken != "" {
		assignments = append(assignments, "sync_token = $sync_token")
		params["sync_token"] = *p.SyncToken
	}
	if p.SyncToken != nil && *p.SyncToken == "" {
		assignments = append(assignments, "sync_token = NONE")
	}

	set := strings.Join(assignments, ", ")
	query := `
		BEGIN TRANSACTION;
		LET $existing = (SELECT * FROM google_calendar_link
			WHERE user = $user AND google_calendar_id = $calendar LIMIT 1)[0];
		IF $existing != NONE {
			UPDATE $existing.id SET ` + set + `;
		} ELSE {
			CREATE google_calendar_link SET
				user = $user, space = $space, google_calendar_id = $calendar, ` + set + `;
		};
		COMMIT TRANSACTION;`

	if _, err := surrealdb.Query[[]any](ctx, store.DB, query, params); err != nil {
		return fmt.Errorf("save google calendar link: %w", err)
	}
	return nil
}

// DeleteCalendarLink stops syncing one calendar and drops the event links
// derived from it, so re-linking starts from a clean full sync.
func (store *GoogleStore) DeleteCalendarLink(ctx context.Context, user models.RecordID, googleCalendarID string) error {
	_, err := surrealdb.Query[[]any](ctx, store.DB, `
		BEGIN TRANSACTION;
		DELETE google_event_link WHERE user = $user AND google_calendar_id = $calendar;
		DELETE google_calendar_link WHERE user = $user AND google_calendar_id = $calendar;
		COMMIT TRANSACTION;`,
		map[string]any{"user": user, "calendar": googleCalendarID},
	)
	if err != nil {
		return fmt.Errorf("delete google calendar link: %w", err)
	}
	return nil
}

// ── Event links ───────────────────────────────────────────────────────────────

// EventLinks returns the uid → Google event map for one calendar. An empty
// googleCalendarID returns every link the user has.
func (store *GoogleStore) EventLinks(ctx context.Context, user models.RecordID, googleCalendarID string) ([]GoogleEventLink, error) {
	query := "SELECT * FROM google_event_link WHERE user = $user"
	params := map[string]any{"user": user}
	if googleCalendarID != "" {
		query += " AND google_calendar_id = $calendar"
		params["calendar"] = googleCalendarID
	}

	results, err := surrealdb.Query[[]dbGoogleEventLink](ctx, store.DB, query+" ORDER BY uid ASC", params)
	if err != nil {
		return nil, fmt.Errorf("list google event links: %w", err)
	}
	out := []GoogleEventLink{}
	for _, qr := range *results {
		for _, row := range qr.Result {
			out = append(out, GoogleEventLink{
				UID:              row.UID,
				GoogleCalendarID: row.GoogleCalendarID,
				GoogleEventID:    row.GoogleEventID,
				ContentHash:      row.ContentHash,
			})
		}
	}
	return out, nil
}

// SaveEventLinks upserts a batch of uid → Google event mappings in one
// transaction. `content_hash` is what stops a second device re-pushing an event
// this one already pushed, so it is written only after the Google call returned.
func (store *GoogleStore) SaveEventLinks(ctx context.Context, user models.RecordID, links []GoogleEventLink) error {
	if len(links) == 0 {
		return nil
	}

	statements := []string{"BEGIN TRANSACTION;"}
	params := map[string]any{"user": user}
	for index, link := range links {
		statements = append(statements, eventLinkUpsert(index, link, params))
	}
	statements = append(statements, "COMMIT TRANSACTION;")

	if _, err := surrealdb.Query[[]any](ctx, store.DB, strings.Join(statements, "\n"), params); err != nil {
		return fmt.Errorf("save google event links: %w", err)
	}
	return nil
}

// eventLinkUpsert renders one indexed upsert of a SaveEventLinks batch and adds
// its parameters to params. A nil content hash means "pushed state unknown", and
// `content_hash` is option<string> — which rejects NULL — so that case is
// written as NONE rather than bound as a nil parameter.
func eventLinkUpsert(index int, link GoogleEventLink, params map[string]any) string {
	suffix := fmt.Sprint(index)
	params["uid"+suffix] = link.UID
	params["calendar"+suffix] = link.GoogleCalendarID
	params["event"+suffix] = link.GoogleEventID

	set := "google_calendar_id = $calendar" + suffix +
		", google_event_id = $event" + suffix +
		", pushed_at = time::now()"
	if link.ContentHash == nil {
		set += ", content_hash = NONE"
	} else {
		set += ", content_hash = $hash" + suffix
		params["hash"+suffix] = *link.ContentHash
	}

	return `
		LET $existing` + suffix + ` = (SELECT * FROM google_event_link
			WHERE user = $user AND uid = $uid` + suffix + ` LIMIT 1)[0];
		IF $existing` + suffix + ` != NONE {
			UPDATE $existing` + suffix + `.id SET ` + set + `;
		} ELSE {
			CREATE google_event_link SET user = $user, uid = $uid` + suffix + `, ` + set + `;
		};`
}

// DeleteEventLink forgets one uid, so the next pass treats it as never pushed.
func (store *GoogleStore) DeleteEventLink(ctx context.Context, user models.RecordID, uid string) error {
	_, err := surrealdb.Query[[]any](ctx, store.DB,
		"DELETE google_event_link WHERE user = $user AND uid = $uid",
		map[string]any{"user": user, "uid": uid},
	)
	if err != nil {
		return fmt.Errorf("delete google event link: %w", err)
	}
	return nil
}
