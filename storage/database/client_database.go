package database

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// Query time budgets. Free-plan tenants share an instance, so a shorter deadline
// caps the damage a slow query does to their neighbours; pro tenants (dedicated)
// get the full budget. An explicit CLIENT_DB_QUERY_TIMEOUT overrides both.
const (
	freePlanQueryTimeout = 8 * time.Second
	proPlanQueryTimeout  = 30 * time.Second
)

// clientDBTimeoutOverride returns the operator-configured query timeout, if any.
func clientDBTimeoutOverride() (time.Duration, bool) {
	if v := os.Getenv("CLIENT_DB_QUERY_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d, true
		}
	}
	return 0, false
}

// clientDBTimeout is the default query budget used where the tenant plan is not
// resolved (e.g. developer-authored migrations). Override with
// CLIENT_DB_QUERY_TIMEOUT (Go duration, e.g. "10s", "2m").
func clientDBTimeout() time.Duration {
	if d, ok := clientDBTimeoutOverride(); ok {
		return d
	}
	return proPlanQueryTimeout
}

// planQueryTimeout is the per-tenant query budget, tighter for free-plan tenants.
func planQueryTimeout(plan string) time.Duration {
	if d, ok := clientDBTimeoutOverride(); ok {
		return d
	}
	if plan == "pro" {
		return proPlanQueryTimeout
	}
	return freePlanQueryTimeout
}

// ProvisionClientDatabase creates a dedicated SurrealDB namespace per client
// (client_{clientID}) holding a database named after the logical name, with a
// DATABASE-scoped OWNER user. Returns the namespace, db name, and password.
//
// One namespace per client makes the tenant a top-level unit (disjoint from the
// system namespace) and the natural placement boundary for future sharding.
//
// DDL identifiers cannot be parameterized in SurrealQL, so clientID and name are
// interpolated directly. Callers must validate both before calling.
func (s *SurrealStore) ProvisionClientDatabase(ctx context.Context, clientID, name string) (namespace, dbName, password string, err error) {
	namespace = clientNamespace(clientID)
	dbName = name

	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", "", "", fmt.Errorf("generate password: %w", err)
	}
	password = base64.RawURLEncoding.EncodeToString(raw)

	// Resolve (provisioning on first use) the org's dedicated instance, then run
	// all DDL against it. Falls back to the shared instance when the feature is
	// off or the client has no organization.
	target, err := s.ensureTargetForClient(ctx, clientID)
	if err != nil {
		return "", "", "", fmt.Errorf("resolve instance: %w", err)
	}
	adminDB, err := s.openAdmin(ctx, target, "", "")
	if err != nil {
		return "", "", "", err
	}
	defer adminDB.Close(ctx) //nolint:errcheck

	// DEFINE NAMESPACE is a root-level statement; the root session runs it without
	// selecting a namespace (selecting an empty one would itself define a "" namespace).
	if _, err = surrealdb.Query[[]any](ctx, adminDB,
		"DEFINE NAMESPACE IF NOT EXISTS `"+namespace+"`",
		nil,
	); err != nil {
		return "", "", "", fmt.Errorf("define namespace: %w", err)
	}

	// Select the namespace with SurrealQL `USE NS` (namespace-only) before defining
	// the database. The driver's Use(ns, "") would select an empty database name and
	// persist a stray "" database inside the namespace. The USE + DEFINE pair returns
	// mixed-shape results, so decode into `any` rather than `[]any`.
	if _, err = surrealdb.Query[any](ctx, adminDB,
		"USE NS `"+namespace+"`; DEFINE DATABASE IF NOT EXISTS `"+dbName+"`;",
		nil,
	); err != nil {
		return "", "", "", fmt.Errorf("define database: %w", err)
	}

	if err = adminDB.Use(ctx, namespace, dbName); err != nil {
		return "", "", "", fmt.Errorf("admin use db: %w", err)
	}
	if _, err = surrealdb.Query[[]any](ctx, adminDB,
		"DEFINE USER IF NOT EXISTS `"+clientID+"_"+name+"` ON DATABASE ROLES OWNER PASSWORD '"+password+"'",
		nil,
	); err != nil {
		return "", "", "", fmt.Errorf("define user: %w", err)
	}

	return namespace, dbName, password, nil
}

// clientNamespace is the per-client SurrealDB namespace name. One namespace per
// client isolates tenants at the top level and is the unit future sharding routes.
func clientNamespace(clientID string) string { return "client_" + clientID }

// ApplyDDLToClientDB connects to the client's database as admin and executes the
// given SurrealQL DDL statements. Callers are responsible for generating safe DDL.
func (s *SurrealStore) ApplyDDLToClientDB(ctx context.Context, namespace, dbName string, stmts []string) error {
	if len(stmts) == 0 {
		return nil
	}

	target, err := s.targetForNamespace(ctx, namespace)
	if err != nil {
		return err
	}
	adminDB, err := s.openAdmin(ctx, target, namespace, dbName)
	if err != nil {
		return err
	}
	defer adminDB.Close(ctx) //nolint:errcheck

	for _, stmt := range stmts {
		if _, err = surrealdb.Query[[]any](ctx, adminDB, stmt, nil); err != nil {
			return fmt.Errorf("apply DDL (%s): %w", stmt, err)
		}
	}
	return nil
}

// beginClientQuery resolves the tenant route, applies the plan-aware timeout and
// per-tenant query admission, and opens a connection to the client database. The
// returned cleanup closes the connection, releases the admission slot, and cancels
// the timeout; callers defer it. The data plane connects as admin (not the per-DB
// OWNER user); row isolation is enforced by resolver subject_user_id filters, and
// namespace isolation by SurrealDB's USE, so admin access avoids storing per-DB
// passwords server-side.
func (s *SurrealStore) beginClientQuery(parent context.Context, namespace, dbName string) (*surrealdb.DB, context.Context, func(), error) {
	route, err := s.routeForNamespace(parent, namespace)
	if err != nil {
		return nil, nil, nil, err
	}

	ctx, cancel := context.WithTimeout(parent, planQueryTimeout(route.plan))

	release, err := s.acquireQuery(ctx, route, namespace)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}

	conn, err := s.openAdmin(ctx, route.target, namespace, dbName)
	if err != nil {
		release()
		cancel()
		return nil, nil, nil, err
	}

	cleanup := func() {
		_ = conn.Close(context.WithoutCancel(ctx))
		release()
		cancel()
	}
	return conn, ctx, cleanup, nil
}

// openAdmin opens a root connection to the given target instance, selecting
// namespace/dbName when both are non-empty (namespace-level statements like
// DEFINE NAMESPACE pass an empty namespace to skip selection).
func (s *SurrealStore) openAdmin(ctx context.Context, target surrealTarget, namespace, dbName string) (*surrealdb.DB, error) {
	conn, err := surrealdb.FromEndpointURLString(ctx, target.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("admin connect: %w", err)
	}
	if _, err = conn.SignIn(ctx, surrealdb.Auth{
		Username: target.User,
		Password: target.Pass,
	}); err != nil {
		_ = conn.Close(ctx)
		return nil, fmt.Errorf("admin sign in: %w", err)
	}
	if namespace != "" {
		if err = conn.Use(ctx, namespace, dbName); err != nil {
			_ = conn.Close(ctx)
			return nil, fmt.Errorf("admin use db: %w", err)
		}
	}
	return conn, nil
}

// ResolveClientDB maps a (clientID, logical name) pair to the physical client
// namespace + database name, mirroring the data plane engine's lookup. Returns an
// error if no active database matches. Dedicated handlers use this before QueryClientDB.
func (s *SurrealStore) ResolveClientDB(ctx context.Context, clientID, name string) (namespace, dbName string, err error) {
	res, err := surrealdb.Query[[]struct {
		Namespace string `json:"namespace"`
		DbName    string `json:"db_name"`
	}](ctx, s.DB, `
		SELECT namespace, db_name FROM client_database
		WHERE client = $client AND name = $name AND status != "deleted"
		LIMIT 1
	`, map[string]any{"client": models.NewRecordID("client", clientID), "name": name})
	if err != nil {
		return "", "", fmt.Errorf("lookup database: %w", err)
	}
	for _, qr := range *res {
		if len(qr.Result) > 0 {
			return qr.Result[0].Namespace, qr.Result[0].DbName, nil
		}
	}
	return "", "", fmt.Errorf("client database %q/%q not found", clientID, name)
}

// QueryClientDB runs a parametrized query against a client database and returns
// the rows of the FIRST statement as generic maps. Use for single-statement
// reads/writes.
func (s *SurrealStore) QueryClientDB(parent context.Context, namespace, dbName, query string, params map[string]any) ([]map[string]any, error) {
	conn, ctx, cleanup, err := s.beginClientQuery(parent, namespace, dbName)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	done := s.queryMetrics.track(namespace, dbName)
	res, err := surrealdb.Query[[]map[string]any](ctx, conn, query, params)
	done()
	if err != nil {
		return nil, err
	}
	for _, qr := range *res {
		return qr.Result, nil
	}
	return nil, nil
}

// QueryClientDBLast runs a parametrized query (typically a multi-statement
// transaction) and returns the rows of the LAST statement — the convention used
// by the versioning transactions, whose final `RETURN [...]` carries the result.
func (s *SurrealStore) QueryClientDBLast(parent context.Context, namespace, dbName, query string, params map[string]any) ([]map[string]any, error) {
	conn, ctx, cleanup, err := s.beginClientQuery(parent, namespace, dbName)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	done := s.queryMetrics.track(namespace, dbName)
	res, err := surrealdb.Query[[]map[string]any](ctx, conn, query, params)
	done()
	if err != nil {
		return nil, err
	}
	results := *res
	if len(results) == 0 {
		return nil, nil
	}
	return results[len(results)-1].Result, nil
}

// RunScopedClientDBStatements executes statements against a client database as a
// DATABASE-scoped OWNER user, NOT the root admin. SurrealDB confines such a
// session to that single database, so arbitrary (developer-authored) migration
// SurrealQL cannot reach other databases, the namespace, or root — structural
// isolation rather than a query denylist.
//
// It provisions an ephemeral scoped user (random password), runs the statements
// as that user, then removes it.
func (s *SurrealStore) RunScopedClientDBStatements(ctx context.Context, namespace, dbName string, stmts []string) error {
	if len(stmts) == 0 {
		return nil
	}

	// Bound the whole run; on timeout the connections close and SurrealDB aborts
	// the uncommitted transaction.
	ctx, cancel := context.WithTimeout(ctx, clientDBTimeout())
	defer cancel()
	closeCtx := context.WithoutCancel(ctx)

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("generate password: %w", err)
	}
	password := base64.RawURLEncoding.EncodeToString(raw)
	const runner = "_mig_runner"

	// Root creates the ephemeral scoped OWNER user in the target database, on the
	// same instance the scoped session will connect to.
	target, err := s.targetForNamespace(ctx, namespace)
	if err != nil {
		return err
	}
	root, err := s.openAdmin(ctx, target, namespace, dbName)
	if err != nil {
		return err
	}
	defer root.Close(closeCtx) //nolint:errcheck
	if _, err = surrealdb.Query[[]any](ctx, root,
		"DEFINE USER OVERWRITE `"+runner+"` ON DATABASE ROLES OWNER PASSWORD '"+password+"'", nil); err != nil {
		return fmt.Errorf("define migration user: %w", err)
	}
	defer func() {
		_, _ = surrealdb.Query[[]any](closeCtx, root, "REMOVE USER `"+runner+"` ON DATABASE", nil)
	}()

	// Run the statements on a session authenticated AS the scoped user, which the
	// engine restricts to this database.
	scoped, err := surrealdb.FromEndpointURLString(ctx, target.Endpoint)
	if err != nil {
		return fmt.Errorf("scoped connect: %w", err)
	}
	defer scoped.Close(closeCtx) //nolint:errcheck
	if _, err = scoped.SignIn(ctx, surrealdb.Auth{
		Namespace: namespace,
		Database:  dbName,
		Username:  runner,
		Password:  password,
	}); err != nil {
		return fmt.Errorf("scoped sign in: %w", err)
	}

	// Wrap all statements in a single transaction: atomic (a failure rolls back
	// every change) and cancelable (closing the connection on timeout aborts it).
	tx := "BEGIN TRANSACTION;\n" + strings.Join(stmts, ";\n") + ";\nCOMMIT TRANSACTION;"
	if _, err = surrealdb.Query[[]any](ctx, scoped, tx, nil); err != nil {
		return fmt.Errorf("apply migration transaction: %w", err)
	}
	return nil
}
