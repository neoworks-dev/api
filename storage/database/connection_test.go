package database

import (
	"context"
	"testing"

	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// TestConnectionLifecycle covers request → accept → list, name-only profile
// resolution without a grant, email exposure once granted, and that a non-member
// (no accepted connection) cannot resolve a profile.
func TestConnectionLifecycle(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")

	suffix := randSuffix()
	aID := "conn_a_" + suffix
	bID := "conn_b_" + suffix
	a := models.NewRecordID("user", aID)
	b := models.NewRecordID("user", bID)

	mustQuery(t, root, "CREATE type::record('user', $id) SET first_name = 'Alice', last_name = 'A', email = $e, password_hash = 'x'",
		map[string]any{"id": aID, "e": aID + "@test.local"})
	mustQuery(t, root, "CREATE type::record('user', $id) SET first_name = 'Bob', last_name = 'B', email = $e, password_hash = 'x'",
		map[string]any{"id": bID, "e": bID + "@test.local"})

	t.Cleanup(func() {
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE connection WHERE in = $a OR out = $a", map[string]any{"a": a})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE sharing_grant WHERE in = $a OR out = $a", map[string]any{"a": a})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $a", map[string]any{"a": a})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $b", map[string]any{"b": b})
	})

	// A requests B.
	if _, err := store.Connections.SendRequest(ctx, a, b); err != nil {
		t.Fatalf("send request: %v", err)
	}
	// Re-sending is idempotent (no error, no duplicate).
	if _, err := store.Connections.SendRequest(ctx, a, b); err != nil {
		t.Fatalf("re-send request: %v", err)
	}

	// Before acceptance there is no accepted connection: profile is hidden.
	if prof, err := store.Connections.ConnectionProfile(ctx, b, a); err != nil || prof != nil {
		t.Fatalf("profile should be nil before acceptance: prof=%v err=%v", prof, err)
	}

	// Only the addressee (B) can accept; A accepting its own request is a no-op.
	if conn, _ := store.Connections.Respond(ctx, a, b, true); conn != nil {
		t.Fatalf("requester must not be able to accept")
	}
	if _, err := store.Connections.Respond(ctx, b, a, true); err != nil {
		t.Fatalf("accept: %v", err)
	}

	// Both endpoints now see one accepted connection.
	accepted := "accepted"
	listA, _ := store.Connections.ListConnections(ctx, a, &accepted)
	listB, _ := store.Connections.ListConnections(ctx, b, &accepted)
	if len(listA) != 1 || len(listB) != 1 {
		t.Fatalf("both should see the connection: a=%d b=%d", len(listA), len(listB))
	}

	// Name-only profile (no grant → email withheld).
	prof, err := store.Connections.ConnectionProfile(ctx, b, a)
	if err != nil || prof == nil {
		t.Fatalf("profile after accept: %v", err)
	}
	if prof.FirstName != "Alice" {
		t.Fatalf("wrong profile: %+v", prof)
	}
	if prof.Email != nil {
		t.Fatalf("email must be withheld without a grant, got %v", *prof.Email)
	}

	// A grants B access to its email; now B sees it.
	if _, err := store.Connections.UpsertGrant(ctx, a, b, []string{"email"}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	prof, _ = store.Connections.ConnectionProfile(ctx, b, a)
	if prof == nil || prof.Email == nil {
		t.Fatalf("email should be visible after grant: %+v", prof)
	}
}
