package database

import (
	"context"
	"testing"
	"time"

	surrealdb "github.com/surrealdb/surrealdb.go"
)

// Verifies schema DDL + data run together in one transaction against a client DB.
func TestMigrationRunsSchemaAndDataInTransaction(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()
	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}

	client := "mig" + randSuffix()
	nsClient, dbName, _, err := store.ProvisionClientDatabase(ctx, client, "db")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")
	t.Cleanup(func() { _, _ = surrealdb.Query[[]any](ctx, root, "REMOVE NAMESPACE `"+nsClient+"`", nil) })

	if err := store.RunScopedClientDBStatements(ctx, nsClient, dbName, []string{
		"DEFINE TABLE note SCHEMALESS",
		"CREATE note:1 SET body = 'hi'",
	}); err != nil {
		t.Fatalf("migration failed: %v", err)
	}

	rootDB := rootConn(t, url, user, pass, nsClient, dbName)
	rows, err := surrealdb.Query[[]map[string]any](ctx, rootDB, "SELECT body FROM note:1", nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if firstString(rows, "body") != "hi" {
		t.Fatalf("expected note created by migration")
	}
}

// Verifies a failing statement rolls back the whole migration (atomic).
func TestMigrationTransactionRollsBackOnError(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()
	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}

	client := "mig" + randSuffix()
	nsClient, dbName, _, err := store.ProvisionClientDatabase(ctx, client, "db")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")
	t.Cleanup(func() { _, _ = surrealdb.Query[[]any](ctx, root, "REMOVE NAMESPACE `"+nsClient+"`", nil) })

	// Second statement is invalid → the whole transaction must roll back.
	err = store.RunScopedClientDBStatements(ctx, nsClient, dbName, []string{
		"CREATE thing:1 SET a = 1",
		"NOT VALID SURREALQL",
	})
	if err == nil {
		t.Fatal("expected migration to fail")
	}

	// Roll back succeeded if the record (and its implicitly-created table) is gone.
	rootDB := rootConn(t, url, user, pass, nsClient, dbName)
	rows, err := surrealdb.Query[[]map[string]any](ctx, rootDB, "SELECT * FROM thing", nil)
	if err != nil {
		return // table never persisted → fully rolled back
	}
	for _, qr := range *rows {
		if len(qr.Result) > 0 {
			t.Fatalf("rollback failed: %d thing rows present after failed migration", len(qr.Result))
		}
	}
}

// Verifies a long-running statement is killed by the timeout instead of blocking.
func TestMigrationTimeoutKillsLongQuery(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()
	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}

	client := "mig" + randSuffix()
	nsClient, dbName, _, err := store.ProvisionClientDatabase(ctx, client, "db")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")
	t.Cleanup(func() { _, _ = surrealdb.Query[[]any](ctx, root, "REMOVE NAMESPACE `"+nsClient+"`", nil) })

	t.Setenv("CLIENT_DB_QUERY_TIMEOUT", "2s")

	// sleep() inside a SELECT is a normal-user-runnable long operation.
	start := time.Now()
	err = store.RunScopedClientDBStatements(ctx, nsClient, dbName, []string{"SELECT * FROM [sleep(10s)]"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if elapsed > 6*time.Second {
		t.Fatalf("query was not killed promptly: took %v (timeout was 2s)", elapsed)
	}
	t.Logf("long query killed after %v (timeout 2s): %v", elapsed, err)
}
