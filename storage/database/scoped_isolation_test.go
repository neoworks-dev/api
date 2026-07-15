package database

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	surrealdb "github.com/surrealdb/surrealdb.go"
)

// These tests validate the STRUCTURAL isolation that migrations rely on: a
// database-scoped SurrealDB user (ROLES OWNER on one database) must not be able
// to reach any other database, the namespace, or root — no matter what SurrealQL
// it runs. They require a running SurrealDB (the dev stack) and are skipped if it
// isn't reachable.

func testEnv() (url, user, pass, ns string) {
	url = os.Getenv("SURREAL_URL")
	if url == "" {
		url = "ws://localhost:8000/rpc"
	}
	user = envOr("SURREAL_USER", "root")
	pass = envOr("SURREAL_PASS", "root")
	ns = envOr("SURREAL_NS", "neoworks")
	return
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func rootConn(t *testing.T, url, user, pass, ns, db string) *surrealdb.DB {
	t.Helper()
	ctx := context.Background()
	conn, err := surrealdb.FromEndpointURLString(ctx, url)
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	if _, err := conn.SignIn(ctx, surrealdb.Auth{Username: user, Password: pass}); err != nil {
		t.Skipf("surreal root sign-in failed: %v", err)
	}
	if err := conn.Use(ctx, ns, db); err != nil {
		t.Fatalf("use %s/%s: %v", ns, db, err)
	}
	return conn
}

func exec(t *testing.T, conn *surrealdb.DB, q string) {
	t.Helper()
	if _, err := surrealdb.Query[[]any](context.Background(), conn, q, nil); err != nil {
		t.Fatalf("setup query failed (%s): %v", q, err)
	}
}

// scopedRaw runs a query as the database-scoped user and returns the ENTIRE
// response serialized as JSON (across all statements), so a leak in any result
// is detectable regardless of shape. This is exactly the privilege migrations
// run with.
func scopedRaw(ctx context.Context, url, ns, db, user, pass, q string) (string, error) {
	conn, err := surrealdb.FromEndpointURLString(ctx, url)
	if err != nil {
		return "", err
	}
	defer conn.Close(ctx) //nolint:errcheck
	if _, err := conn.SignIn(ctx, surrealdb.Auth{Namespace: ns, Database: db, Username: user, Password: pass}); err != nil {
		return "", err
	}
	res, err := surrealdb.Query[any](ctx, conn, q, nil)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(res)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func TestScopedUserCannotEscapeSandbox(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}

	victimDB := "test_victim_" + randSuffix()
	attackerClient := "atk" + randSuffix()
	attackerName := "db"
	pinInstance(store, url, user, pass, attackerClient)

	root := rootConn(t, url, user, pass, ns, "auth")

	// Victim database holds a secret the attacker must never read or destroy.
	exec(t, root, "DEFINE DATABASE `"+victimDB+"`")
	root2 := rootConn(t, url, user, pass, ns, victimDB)
	exec(t, root2, "DEFINE TABLE secret SCHEMALESS")
	exec(t, root2, "CREATE secret:1 SET data = 'topsecret'")

	// Attacker database provisioned the normal way: its own per-client namespace
	// with a db-scoped OWNER user. The victim DB lives in a DIFFERENT namespace, so
	// these escapes also exercise cross-namespace isolation.
	attackerNS, attackerDB, attackerPass, err := store.ProvisionClientDatabase(ctx, attackerClient, attackerName)
	if err != nil {
		t.Fatalf("provision attacker db: %v", err)
	}
	attackerUser := attackerClient + "_" + attackerName

	t.Cleanup(func() {
		_, _ = surrealdb.Query[[]any](ctx, root, "REMOVE DATABASE `"+victimDB+"`", nil)
		_, _ = surrealdb.Query[[]any](ctx, root, "REMOVE NAMESPACE `"+attackerNS+"`", nil)
	})

	// ── Escape attempts: each runs as the scoped attacker user ──────────────────
	escapes := []string{
		// Cross-database hop via USE.
		"USE NS " + ns + " DB `" + victimDB + "`; SELECT * FROM secret;",
		"USE DB `" + victimDB + "`; SELECT * FROM secret;",
		// Read the platform auth database (users / password hashes).
		"USE NS " + ns + " DB auth; SELECT * FROM user;",
		// Privilege escalation.
		"DEFINE USER hacker ON ROOT PASSWORD 'pw' ROLES OWNER;",
		"DEFINE USER hacker ON NAMESPACE PASSWORD 'pw' ROLES OWNER;",
		// Inspect/alter beyond the database.
		"INFO FOR ROOT;",
		"INFO FOR NS;",
		"DEFINE DATABASE evil_db;",
		"REMOVE DATABASE `" + victimDB + "`;",
	}

	for _, q := range escapes {
		raw, err := scopedRaw(ctx, url, attackerNS, attackerDB, attackerUser, attackerPass, q)
		if err != nil {
			t.Logf("escape blocked with error (good): %q -> %v", oneLine(q), err)
			continue
		}
		// No error: the full response must not contain any cross-database secret.
		if strings.Contains(raw, "topsecret") {
			t.Errorf("LEAK: scoped user read victim secret via %q -> %s", oneLine(q), raw)
		}
		if strings.Contains(raw, "password_hash") {
			t.Errorf("LEAK: scoped user read auth.user via %q -> %s", oneLine(q), raw)
		}
		t.Logf("escape returned no sensitive data (good): %q", oneLine(q))
	}

	// ── Post-conditions: nothing outside the attacker DB was mangled ────────────
	// Victim secret still intact.
	vrows, err := surrealdb.Query[[]map[string]any](ctx, root2, "SELECT data FROM secret:1", nil)
	if err != nil {
		t.Fatalf("verify victim: %v", err)
	}
	if got := firstString(vrows, "data"); got != "topsecret" {
		t.Fatalf("victim secret was tampered with: got %q", got)
	}
	// No root user was created.
	if rootUserExists(t, root, "hacker") {
		t.Fatal("scoped user escalated to a ROOT user")
	}
	// No rogue database was created.
	if databaseExists(t, root, "evil_db") {
		t.Fatal("scoped user created a database outside its sandbox")
	}

	// ── Positive: legitimate work WITHIN the attacker DB still succeeds ─────────
	if _, err := scopedRaw(ctx, url, attackerNS, attackerDB, attackerUser, attackerPass,
		"DEFINE TABLE thing SCHEMALESS; CREATE thing SET ok = true;"); err != nil {
		t.Fatalf("scoped user could not do legitimate in-db work: %v", err)
	}
	raw, err := scopedRaw(ctx, url, attackerNS, attackerDB, attackerUser, attackerPass, "SELECT * FROM thing")
	if err != nil || !strings.Contains(raw, "ok") {
		t.Fatalf("scoped user could not read its own data: err=%v raw=%s", err, raw)
	}
}

// TestRunScopedClientDBStatementsContainsDestructiveSQL exercises the real
// migration runner with destructive cross-db SurrealQL and confirms the victim
// database survives.
func TestRunScopedClientDBStatementsContainsDestructiveSQL(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}

	victimDB := "test_victim_" + randSuffix()
	attackerClient := "atk" + randSuffix()
	pinInstance(store, url, user, pass, attackerClient)

	root := rootConn(t, url, user, pass, ns, "auth")
	exec(t, root, "DEFINE DATABASE `"+victimDB+"`")
	rootV := rootConn(t, url, user, pass, ns, victimDB)
	exec(t, rootV, "DEFINE TABLE secret SCHEMALESS")
	exec(t, rootV, "CREATE secret:1 SET data = 'keepme'")

	attackerNS, attackerDB, _, err := store.ProvisionClientDatabase(ctx, attackerClient, "db")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() {
		_, _ = surrealdb.Query[[]any](ctx, root, "REMOVE DATABASE `"+victimDB+"`", nil)
		_, _ = surrealdb.Query[[]any](ctx, root, "REMOVE NAMESPACE `"+attackerNS+"`", nil)
	})

	// The runner may return an error for these — that's fine. What matters is the
	// victim is untouched afterwards.
	_ = store.RunScopedClientDBStatements(ctx, attackerNS, attackerDB, []string{
		"REMOVE DATABASE `" + victimDB + "`",
	})
	_ = store.RunScopedClientDBStatements(ctx, attackerNS, attackerDB, []string{
		"USE NS " + ns + " DB `" + victimDB + "`; UPDATE secret:1 SET data = 'pwned';",
	})
	_ = store.RunScopedClientDBStatements(ctx, attackerNS, attackerDB, []string{
		"DEFINE USER hacker ON ROOT PASSWORD 'pw' ROLES OWNER",
	})

	rows, err := surrealdb.Query[[]map[string]any](ctx, rootV, "SELECT data FROM secret:1", nil)
	if err != nil {
		t.Fatalf("verify victim: %v", err)
	}
	if got := firstString(rows, "data"); got != "keepme" {
		t.Fatalf("victim secret tampered: got %q", got)
	}
	if rootUserExists(t, root, "hacker") {
		t.Fatal("migration runner escalated to ROOT")
	}
}

// TestScopedUserCannotReachAnotherClientNamespace provisions two client databases
// the normal way — each in its own namespace — and confirms client A's scoped user
// cannot read client B's data. This is the top-level tenant guarantee one-namespace-
// per-client buys: isolation no longer rests on database-within-shared-namespace.
func TestScopedUserCannotReachAnotherClientNamespace(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}

	clientA := "atk" + randSuffix()
	clientB := "vic" + randSuffix()
	pinInstance(store, url, user, pass, clientA, clientB)

	nsA, dbA, passA, err := store.ProvisionClientDatabase(ctx, clientA, "db")
	if err != nil {
		t.Fatalf("provision A: %v", err)
	}
	nsB, dbB, _, err := store.ProvisionClientDatabase(ctx, clientB, "db")
	if err != nil {
		t.Fatalf("provision B: %v", err)
	}
	userA := clientA + "_db"

	root := rootConn(t, url, user, pass, ns, "auth")
	t.Cleanup(func() {
		_, _ = surrealdb.Query[[]any](ctx, root, "REMOVE NAMESPACE `"+nsA+"`", nil)
		_, _ = surrealdb.Query[[]any](ctx, root, "REMOVE NAMESPACE `"+nsB+"`", nil)
	})

	// Seed a secret into client B's database (as root, in B's namespace).
	rootB := rootConn(t, url, user, pass, nsB, dbB)
	exec(t, rootB, "DEFINE TABLE secret SCHEMALESS")
	exec(t, rootB, "CREATE secret:1 SET data = 'tenantB'")

	// Client A's scoped user tries to hop into B's namespace.
	escapes := []string{
		"USE NS " + nsB + " DB `" + dbB + "`; SELECT * FROM secret;",
		"INFO FOR ROOT;",
		"INFO FOR NS;",
	}
	for _, q := range escapes {
		raw, err := scopedRaw(ctx, url, nsA, dbA, userA, passA, q)
		if err != nil {
			t.Logf("cross-namespace blocked with error (good): %q -> %v", oneLine(q), err)
			continue
		}
		if strings.Contains(raw, "tenantB") {
			t.Errorf("LEAK: client A read client B across namespaces via %q -> %s", oneLine(q), raw)
		}
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

// pinInstance routes synthetic client ids at the live test SurrealDB by seeding
// the store's target cache, so ProvisionClientDatabase and scoped runs hit that
// instance without needing a provisioner or real client/org records. Keeping
// both clients on one instance is what makes these cross-namespace isolation
// checks meaningful.
func pinInstance(store *SurrealStore, url, user, pass string, clientIDs ...string) {
	for _, id := range clientIDs {
		store.targets.put(id, tenantRoute{
			target: surrealTarget{Endpoint: url, User: user, Pass: pass},
			plan:   "pro",
		})
	}
}

func firstString(res *[]surrealdb.QueryResult[[]map[string]any], key string) string {
	for _, qr := range *res {
		for _, row := range qr.Result {
			if v, ok := row[key].(string); ok {
				return v
			}
		}
	}
	return ""
}

func rootUserExists(t *testing.T, root *surrealdb.DB, name string) bool {
	t.Helper()
	res, err := surrealdb.Query[map[string]any](context.Background(), root, "INFO FOR ROOT", nil)
	if err != nil {
		return false
	}
	for _, qr := range *res {
		users, _ := qr.Result["users"].(map[string]any)
		if _, ok := users[name]; ok {
			return true
		}
	}
	return false
}

func databaseExists(t *testing.T, root *surrealdb.DB, name string) bool {
	t.Helper()
	res, err := surrealdb.Query[map[string]any](context.Background(), root, "INFO FOR NS", nil)
	if err != nil {
		return false
	}
	for _, qr := range *res {
		dbs, _ := qr.Result["databases"].(map[string]any)
		if _, ok := dbs[name]; ok {
			return true
		}
	}
	return false
}

func oneLine(s string) string { return strings.ReplaceAll(s, "\n", " ") }

var randCounter int

func randSuffix() string {
	randCounter++
	// Deterministic-enough unique suffix for a single test run.
	b := make([]byte, 0, 8)
	n := randCounter
	for i := 0; i < 6; i++ {
		b = append(b, byte('a'+(n%26)))
		n /= 26
	}
	return string(b)
}
