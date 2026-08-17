package database

import (
	"context"
	"testing"

	surrealdb "github.com/surrealdb/surrealdb.go"
)

// Helpers shared by the store tests. They used to live in the event store's
// test file, which went away with server-side calendars.

func strptr(s string) *string { return &s }
func intptr(i int) *int       { return &i }

// mustQuery runs a setup statement and fails the test if it errors, so fixtures
// never fail silently and leave a later assertion to explain it.
func mustQuery(t *testing.T, conn *surrealdb.DB, q string, vars map[string]any) {
	t.Helper()
	if _, err := surrealdb.Query[[]any](context.Background(), conn, q, vars); err != nil {
		t.Fatalf("setup query failed (%s): %v", q, err)
	}
}
