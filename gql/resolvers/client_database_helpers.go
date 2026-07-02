package gql

import (
	"context"
	"fmt"
	"sort"
	"strings"

	gql_model "github.com/neoworks/auth/gql/model"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/database"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

func firstResult(results *[]surrealdb.QueryResult[[]oauth.ClientDatabase]) *oauth.ClientDatabase {
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			rec := qr.Result[0]
			return &rec
		}
	}
	return nil
}

func (r *mutationResolver) countClientDatabases(ctx context.Context, clientRef models.RecordID) (int, error) {
	results, err := surrealdb.Query[[]struct {
		Count int `json:"count"`
	}](ctx, r.store.DB, `
		SELECT count() AS count FROM client_database
		WHERE client = $client AND status != "deleted"
		GROUP ALL
	`, map[string]any{"client": clientRef})
	if err != nil {
		return 0, fmt.Errorf("count databases: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0].Count, nil
		}
	}
	return 0, nil
}

// clientOrganization returns the owning organization of a client, used to route
// client usage to the org's billing identity. Returns nil if it cannot be resolved.
func (r *mutationResolver) clientOrganization(ctx context.Context, clientRef models.RecordID) *models.RecordID {
	results, err := surrealdb.Query[[]*models.RecordID](ctx, r.store.DB,
		"SELECT VALUE organization FROM client WHERE id = $client LIMIT 1",
		map[string]any{"client": clientRef},
	)
	if err != nil {
		return nil
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0]
		}
	}
	return nil
}

// recordClientTables writes the validated table registry for a database. The
// registry is the source GraphQL endpoints are generated from — never raw input.
func (r *mutationResolver) recordClientTables(ctx context.Context, dbID *models.RecordID, schema *gql_model.DatabaseSchemaInput, tables []rewrittenTable) error {
	if dbID == nil || schema == nil {
		return nil
	}

	// Replace any prior registry rows for this database.
	if _, err := surrealdb.Query[[]any](ctx, r.store.DB,
		"DELETE client_table WHERE database = $db",
		map[string]any{"db": *dbID},
	); err != nil {
		return err
	}

	// Synthetic DDL-only entries (e.g. the prepended `_analyzers`) carry no kind and
	// are not real client tables — skip them so they neither violate the kind ASSERT
	// nor shift the index alignment with schema.Tables. The remaining entries are in
	// submission order, one per input table.
	tableIndex := 0
	for _, rt := range tables {
		if rt.kind == "" {
			continue
		}
		var validated any
		if tableIndex < len(schema.Tables) {
			validated = schema.Tables[tableIndex]
		}
		if err := r.createClientTableRow(ctx, *dbID, rt, validated); err != nil {
			return err
		}
		tableIndex++
	}
	return nil
}

// createClientTableRow inserts one client_table registry row. Data tables have
// no subject_path; the field is omitted entirely so it defaults to NONE rather
// than being set to a nil that the driver would send as a rejected SQL NULL.
func (r *mutationResolver) createClientTableRow(ctx context.Context, dbID models.RecordID, rt rewrittenTable, validated any) error {
	assignments := []string{
		"database = $db",
		"name = $name",
		"kind = $kind",
		"versioned = $versioned",
		"has_subject_user = $has_subject_user",
		"validated_schema = $validated_schema",
	}
	params := map[string]any{
		"db":               dbID,
		"name":             rt.name,
		"kind":             rt.kind,
		"versioned":        rt.versioned,
		"has_subject_user": rt.hasSubjectUser,
		"validated_schema": validated,
	}
	if rt.subjectPath != "" {
		assignments = append(assignments, "subject_path = $subject_path")
		params["subject_path"] = rt.subjectPath
	}

	query := "CREATE client_table SET " + strings.Join(assignments, ", ")
	if _, err := surrealdb.Query[[]any](ctx, r.store.DB, query, params); err != nil {
		return err
	}
	return nil
}

// ── Migrations ──────────────────────────────────────────────────────────────

// reserved table that tracks applied migration versions inside each client DB.
const migrationTable = "_migration"

func migrationTableDDL() []string {
	return []string{
		"DEFINE TABLE IF NOT EXISTS `" + migrationTable + "` SCHEMAFULL;",
		"DEFINE FIELD OVERWRITE `version` ON `" + migrationTable + "` TYPE int;",
		"DEFINE FIELD OVERWRITE `name` ON `" + migrationTable + "` TYPE string;",
		"DEFINE FIELD OVERWRITE `applied_at` ON `" + migrationTable + "` TYPE datetime VALUE time::now() READONLY;",
		"DEFINE INDEX OVERWRITE `idx_migration_version` ON `" + migrationTable + "` FIELDS `version` UNIQUE;",
	}
}

func (r *mutationResolver) getClientDatabase(ctx context.Context, clientRef models.RecordID, name string) (*oauth.ClientDatabase, error) {
	results, err := surrealdb.Query[[]oauth.ClientDatabase](ctx, r.store.DB, `
		SELECT * FROM client_database
		WHERE client = $client AND name = $name AND status != "deleted"
		LIMIT 1
	`, map[string]any{"client": clientRef, "name": name})
	if err != nil {
		return nil, fmt.Errorf("lookup database: %w", err)
	}
	rec := firstResult(results)
	if rec == nil {
		return nil, database.ErrNotFound
	}
	return rec, nil
}

// currentMigrationVersion returns the highest applied migration version, or 0.
func (r *mutationResolver) currentMigrationVersion(ctx context.Context, namespace, dbName string) (int, error) {
	rows, err := r.store.QueryClientDB(ctx, namespace, dbName,
		"SELECT version FROM `"+migrationTable+"` ORDER BY version DESC LIMIT 1", nil)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	switch v := rows[0]["version"].(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	case uint64:
		return int(v), nil
	default:
		return 0, nil
	}
}

func (r *mutationResolver) recordMigration(ctx context.Context, namespace, dbName string, version int, name string) error {
	_, err := r.store.QueryClientDB(ctx, namespace, dbName,
		"CREATE `"+migrationTable+"` SET version = $version, name = $name",
		map[string]any{"version": version, "name": name})
	return err
}

// applyMigrations runs ordered, not-yet-applied migrations (declarative schema +
// imperative SurrealQL) against a client database, tracking applied versions.
// Caller must be a member of the database's owning organization.
func (r *mutationResolver) applyMigrations(ctx context.Context, clientID string, name string, migrations []*gql_model.MigrationInput) (*gql_model.MigrationResult, error) {
	claim := middleware.ClaimFromContext(ctx)
	if claim == nil {
		return nil, errUnauthenticated
	}
	clientRef := models.NewRecordID("client", clientID)

	orgRef := r.clientOrganization(ctx, clientRef)
	if orgRef == nil || !r.callerIsMember(ctx, claim.Subject, *orgRef) {
		return nil, Public("forbidden: not a member of the database's organization")
	}

	rec, err := r.getClientDatabase(ctx, clientRef, name)
	if err != nil {
		return nil, err
	}

	if err := r.store.ApplyDDLToClientDB(ctx, rec.Namespace, rec.DbName, migrationTableDDL()); err != nil {
		return nil, fmt.Errorf("ensure migration table: %w", err)
	}

	current, err := r.currentMigrationVersion(ctx, rec.Namespace, rec.DbName)
	if err != nil {
		return nil, fmt.Errorf("read migration version: %w", err)
	}

	sorted := make([]*gql_model.MigrationInput, 0, len(migrations))
	for _, m := range migrations {
		if m != nil {
			sorted = append(sorted, m)
		}
	}
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Version < sorted[j].Version })

	var applied []int
	var lastSchema *gql_model.DatabaseSchemaInput
	var lastTables []rewrittenTable

	for _, m := range sorted {
		if m.Version <= current {
			continue
		}
		var stmts []string
		if m.SchemaSource != nil && *m.SchemaSource != "" {
			schema, err := compileSchemaSource(ctx, *m.SchemaSource)
			if err != nil {
				return nil, fmt.Errorf("migration %d schema: %w", m.Version, err)
			}
			tables, err := rewriteSchemaInput(schema)
			if err != nil {
				return nil, fmt.Errorf("migration %d schema: %w", m.Version, err)
			}
			stmts = append(stmts, allDDL(tables)...)
			lastSchema = schema
			lastTables = tables
		}
		stmts = append(stmts, m.Statements...)
		// Run as a DATABASE-scoped user so SurrealDB structurally confines the
		// (developer-authored) SurrealQL to this one database.
		if err := r.store.RunScopedClientDBStatements(ctx, rec.Namespace, rec.DbName, stmts); err != nil {
			return nil, fmt.Errorf("migration %d (%s): %w", m.Version, m.Name, err)
		}
		if err := r.recordMigration(ctx, rec.Namespace, rec.DbName, m.Version, m.Name); err != nil {
			return nil, fmt.Errorf("record migration %d: %w", m.Version, err)
		}
		applied = append(applied, m.Version)
		current = m.Version
	}

	// If any migration changed the schema, refresh the registry + generated GraphQL.
	if lastSchema != nil {
		if err := r.recordClientTables(ctx, rec.ID, lastSchema, lastTables); err != nil {
			return nil, fmt.Errorf("record client tables: %w", err)
		}
		if _, err := surrealdb.Query[[]any](ctx, r.store.DB,
			"UPDATE client_database SET schema_def = $schema WHERE id = $id",
			map[string]any{"schema": lastSchema, "id": rec.ID}); err != nil {
			return nil, fmt.Errorf("update schema_def: %w", err)
		}
		if r.engine != nil {
			r.engine.Invalidate(clientID, name)
		}
	}

	return &gql_model.MigrationResult{Applied: applied, CurrentVersion: current}, nil
}
