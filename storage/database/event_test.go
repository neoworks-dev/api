package database

import (
	"context"
	"errors"
	"testing"
	"time"

	gql_model "github.com/neoworks/auth/gql/model"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

func strptr(s string) *string { return &s }
func intptr(i int) *int       { return &i }

// TestEventStoreOwnerSharing verifies the user-owned access model: the owner can
// CRUD their events and calendars; an unrelated user is denied; and an invited
// participant gains read (while pending) then edit (once accepted) access to the
// single shared event, but never the right to delete it. Requires a running
// SurrealDB with calendar migrations applied; skipped otherwise.
func TestEventStoreOwnerSharing(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")

	suffix := randSuffix()
	ownerID := "evt_owner_" + suffix
	inviteeID := "evt_invitee_" + suffix
	outsiderID := "evt_outsider_" + suffix

	owner := models.NewRecordID("user", ownerID)
	invitee := models.NewRecordID("user", inviteeID)
	outsider := models.NewRecordID("user", outsiderID)

	mkUser := func(id string) {
		mustQuery(t, root, "CREATE type::record('user', $id) SET first_name = 'Test', last_name = 'User', email = $email, password_hash = 'x'",
			map[string]any{"id": id, "email": id + "@test.local"})
	}
	mkUser(ownerID)
	mkUser(inviteeID)
	mkUser(outsiderID)

	t.Cleanup(func() {
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE attendance WHERE in = $u OR in = $o", map[string]any{"u": invitee, "o": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE event WHERE owner = $o", map[string]any{"o": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE calendar WHERE owner = $o", map[string]any{"o": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": invitee})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": outsider})
	})

	// ── Create (as owner) ─────────────────────────────────────────────────────────
	startLocal := time.Now().Add(time.Hour).UTC().Truncate(time.Second).Format(localDateTimeLayout)
	created, err := store.Events.Create(ctx, &CreateEventParams{
		Owner: owner,
		UID:   "uid_" + suffix,
		Fields: EventFields{
			Title:    strptr("Family dinner"),
			Start:    strptr(startLocal),
			Duration: strptr("PT1H"),
			TimeZone: strptr("UTC"),
			Keywords: []string{"food", "family"},
		},
	})
	if err != nil {
		t.Fatalf("create event: %v", err)
	}
	if created.Title != "Family dinner" || len(created.Keywords) != 2 {
		t.Fatalf("unexpected created event: %+v", created)
	}
	if created.MyAttendance == nil || *created.MyAttendance != "owner" {
		t.Fatalf("owner my_attendance should be \"owner\", got %v", created.MyAttendance)
	}
	eventRef := models.NewRecordID("event", created.ID)

	// ── Owner reads it; outsider is denied ──────────────────────────────────────────
	if got, err := store.Events.Get(ctx, eventRef, owner); err != nil || got.ID != created.ID {
		t.Fatalf("owner get: err=%v", err)
	}
	if _, err := store.Events.Get(ctx, eventRef, outsider); !errors.Is(err, ErrNotFound) {
		t.Fatalf("outsider get should be ErrNotFound, got: %v", err)
	}
	if listed, err := store.Events.ListForUser(ctx, owner, nil, nil, nil); err != nil || len(listed) != 1 {
		t.Fatalf("owner list: err=%v len=%d", err, len(listed))
	}
	if listed, err := store.Events.ListForUser(ctx, outsider, nil, nil, nil); err != nil || len(listed) != 0 {
		t.Fatalf("outsider list should be empty: err=%v len=%d", err, len(listed))
	}

	// ── Invite the invitee (pending) ────────────────────────────────────────────────
	added, err := store.Events.SyncAttendance(ctx, eventRef, owner, []string{inviteeID}, nil)
	if err != nil || len(added) != 1 || added[0] != inviteeID {
		t.Fatalf("sync attendance: err=%v added=%v", err, added)
	}
	// A pending invitee can see the event...
	got, err := store.Events.Get(ctx, eventRef, invitee)
	if err != nil {
		t.Fatalf("invitee (pending) get: %v", err)
	}
	if got.MyAttendance == nil || *got.MyAttendance != "pending" {
		t.Fatalf("invitee my_attendance should be \"pending\", got %v", got.MyAttendance)
	}
	// ...but cannot edit it yet.
	pendingEdit := "Hijack"
	if _, err := store.Events.Update(ctx, &UpdateEventParams{ID: eventRef, UserID: invitee, Fields: EventFields{Title: &pendingEdit}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pending invitee update should be ErrNotFound, got: %v", err)
	}

	// ── Accept → invitee can now read and edit the shared event ──────────────────────
	accepted, err := store.Events.RespondToInvite(ctx, eventRef, invitee, true)
	if err != nil || accepted == nil || *accepted.MyAttendance != "accepted" {
		t.Fatalf("accept invite: err=%v ev=%+v", err, accepted)
	}
	if listed, err := store.Events.ListForUser(ctx, invitee, nil, nil, nil); err != nil || len(listed) != 1 {
		t.Fatalf("accepted invitee list: err=%v len=%d", err, len(listed))
	}
	sharedTitle := "Family lunch"
	if updated, err := store.Events.Update(ctx, &UpdateEventParams{ID: eventRef, UserID: invitee, Fields: EventFields{Title: &sharedTitle}}); err != nil || updated.Title != sharedTitle {
		t.Fatalf("accepted invitee edit: err=%v title=%q", err, updated.Title)
	}
	// The owner sees the invitee's edit on the single shared record.
	if got, err := store.Events.Get(ctx, eventRef, owner); err != nil || got.Title != sharedTitle {
		t.Fatalf("owner sees shared edit: err=%v title=%q", err, got.Title)
	}

	// ── Delete is owner-only ──────────────────────────────────────────────────────
	if err := store.Events.Delete(ctx, eventRef, invitee); err != nil {
		t.Fatalf("invitee delete should be a no-op, got: %v", err)
	}
	if _, err := store.Events.Get(ctx, eventRef, owner); err != nil {
		t.Fatalf("event should survive an invitee delete: %v", err)
	}

	// ── Decline drops the event from the invitee's view ──────────────────────────────
	if ev, err := store.Events.RespondToInvite(ctx, eventRef, invitee, false); err != nil || ev != nil {
		t.Fatalf("decline invite: err=%v ev=%v", err, ev)
	}
	if listed, err := store.Events.ListForUser(ctx, invitee, nil, nil, nil); err != nil || len(listed) != 0 {
		t.Fatalf("declined invitee list should be empty: err=%v len=%d", err, len(listed))
	}

	// ── Calendars are owner-scoped ────────────────────────────────────────────────
	cal, err := store.Calendars.Create(ctx, &CreateCalendarParams{Owner: owner, Name: "Health", Color: "green"})
	if err != nil {
		t.Fatalf("create calendar: %v", err)
	}
	calRef := models.NewRecordID("calendar", cal.ID)
	if _, err := store.Calendars.Get(ctx, calRef, outsider); !errors.Is(err, ErrNotFound) {
		t.Fatalf("outsider calendar get should be ErrNotFound, got: %v", err)
	}

	// ── Owner delete ──────────────────────────────────────────────────────────────
	if err := store.Events.Delete(ctx, eventRef, owner); err != nil {
		t.Fatalf("owner delete: %v", err)
	}
	if _, err := store.Events.Get(ctx, eventRef, owner); !errors.Is(err, ErrNotFound) {
		t.Fatalf("event should be gone after owner delete, got: %v", err)
	}
}

// TestEventFilter proves the shared filter compiler works for a second entity:
// it drives EventFilter (string/int/stringList/date + and/or/not) through the
// same engine as contacts.
func TestEventFilter(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()
	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")

	suffix := randSuffix()
	ownerID := "evtf_owner_" + suffix
	owner := models.NewRecordID("user", ownerID)

	mustQuery(t, root, "CREATE type::record('user', $id) SET first_name='T', last_name='M', email=$e, password_hash='x'",
		map[string]any{"id": ownerID, "e": ownerID + "@test.local"})
	t.Cleanup(func() {
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE event WHERE owner = $o", map[string]any{"o": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": owner})
	})

	start := time.Now().Add(time.Hour).UTC().Truncate(time.Second).Format(localDateTimeLayout)
	mk := func(title, status string, priority int, keywords []string) {
		_, err := store.Events.Create(ctx, &CreateEventParams{
			Owner: owner, UID: title + "_" + suffix,
			Fields: EventFields{
				Title: strptr(title), Start: strptr(start), TimeZone: strptr("UTC"),
				Status: strptr(status), Priority: intptr(priority), Keywords: keywords,
			},
		})
		if err != nil {
			t.Fatalf("create %s: %v", title, err)
		}
	}
	mk("Standup", "confirmed", 5, []string{"work", "daily"})
	mk("Sprint Review", "confirmed", 9, []string{"work"})
	mk("Dentist", "tentative", 1, []string{"health"})

	run := func(name string, f *gql_model.EventFilter, want int) {
		got, err := store.Events.ListForUser(ctx, owner, nil, nil, f)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != want {
			titles := make([]string, len(got))
			for i, e := range got {
				titles[i] = e.Title
			}
			t.Fatalf("%s: want %d, got %d (%v)", name, want, len(got), titles)
		}
	}
	str := func(s string) *string { return &s }

	// status eq → the two confirmed events.
	run("status confirmed", &gql_model.EventFilter{Status: &gql_model.StringFilter{Eq: str("confirmed")}}, 2)

	// priority > 4 → Standup (5) + Sprint Review (9).
	run("priority gt 4", &gql_model.EventFilter{Priority: &gql_model.IntFilter{Gt: intptr(4)}}, 2)

	// keywords hasAny work → Standup + Sprint Review.
	run("keyword work", &gql_model.EventFilter{Keywords: &gql_model.StringListFilter{HasAny: []string{"work"}}}, 2)

	// title contains "sprint" (case-insensitive) → Sprint Review.
	run("title contains sprint", &gql_model.EventFilter{Title: &gql_model.StringFilter{Contains: str("sprint")}}, 1)

	// or: tentative status OR priority >= 9 → Dentist + Sprint Review.
	run("tentative or high prio", &gql_model.EventFilter{
		Or: []*gql_model.EventFilter{
			{Status: &gql_model.StringFilter{Eq: str("tentative")}},
			{Priority: &gql_model.IntFilter{Gt: intptr(8)}},
		},
	}, 2)

	// not (status confirmed) → only Dentist.
	run("not confirmed", &gql_model.EventFilter{
		Not: &gql_model.EventFilter{Status: &gql_model.StringFilter{Eq: str("confirmed")}},
	}, 1)
}

// TestEventUpdateRecurrence reproduces adding a recurrence rule (with an `until`)
// via Update — the path that returned an internal server error in the app.
func TestEventUpdateRecurrence(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")

	suffix := randSuffix()
	ownerID := "rec_owner_" + suffix
	owner := models.NewRecordID("user", ownerID)

	mustQuery(t, root, "CREATE type::record('user', $id) SET first_name = 'Test', last_name = 'Owner', email = $email, password_hash = 'x'",
		map[string]any{"id": ownerID, "email": ownerID + "@test.local"})

	t.Cleanup(func() {
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE event WHERE owner = $o", map[string]any{"o": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": owner})
	})

	startLocal := time.Now().Add(time.Hour).UTC().Truncate(time.Second).Format(localDateTimeLayout)
	created, err := store.Events.Create(ctx, &CreateEventParams{
		Owner: owner, UID: "uid_" + suffix,
		Fields: EventFields{
			Title:    strptr("Design System Class"),
			Start:    strptr(startLocal),
			Duration: strptr("PT2H"),
			TimeZone: strptr("UTC"),
		},
	})
	if err != nil {
		t.Fatalf("create event: %v", err)
	}
	eventRef := models.NewRecordID("event", created.ID)

	interval := 1
	until := "2026-06-30T21:59:00"
	updated, err := store.Events.Update(ctx, &UpdateEventParams{
		ID:     eventRef,
		UserID: owner,
		Fields: EventFields{
			RecurrenceRules: []RecurrenceRuleData{{Frequency: "daily", Interval: &interval, Until: &until}},
		},
	})
	if err != nil {
		t.Fatalf("update with recurrence: %v", err)
	}
	if len(updated.RecurrenceRules) != 1 || updated.RecurrenceRules[0].Frequency != "daily" {
		t.Fatalf("recurrence not persisted: %+v", updated.RecurrenceRules)
	}

	// Clearing: a present-but-empty slice removes the stored rule.
	cleared, err := store.Events.Update(ctx, &UpdateEventParams{
		ID:     eventRef,
		UserID: owner,
		Fields: EventFields{RecurrenceRules: []RecurrenceRuleData{}},
	})
	if err != nil {
		t.Fatalf("update clearing recurrence: %v", err)
	}
	if len(cleared.RecurrenceRules) != 0 {
		t.Fatalf("recurrence not cleared: %+v", cleared.RecurrenceRules)
	}
}

func mustQuery(t *testing.T, conn *surrealdb.DB, q string, vars map[string]any) {
	t.Helper()
	if _, err := surrealdb.Query[[]any](context.Background(), conn, q, vars); err != nil {
		t.Fatalf("setup query failed (%s): %v", q, err)
	}
}
