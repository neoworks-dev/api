package gql

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	gql_model "github.com/neoworks/auth/gql/model"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/database"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// The OpenSchema public registry (openschema.neoworks.dev) is a neoworks client
// backed by one client_database. The registry/discussion data lives in shared
// tables (org-wide, publicly readable); drafts live in a per-user data table.
const (
	openschemaClientID   = "openschema"
	openschemaRegistryDB = "registry"
)

// The registry dogfoods the OpenSchema DSL: registry.schema is the canonical
// source, authored with @neoworks.* decorators, and registry.internal.json is the
// committed compiled artifact (regenerate with `bun run gen:registry`). Boot
// seeding decodes the embedded JSON so it never depends on the compile sidecar.

//go:embed registry.schema
var registrySchemaSource string

//go:embed registry.internal.json
var registrySchemaJSON []byte

// registry.ddl.json is the SurrealQL the OpenSchema compiler emits for the
// registry schema, committed so boot seeding applies it without the compile
// sidecar. Regenerate both artifacts with `bun run gen:registry`.
//
//go:embed registry.ddl.json
var registryDDLJSON []byte

func registrySchema() (*gql_model.DatabaseSchemaInput, error) {
	var schema gql_model.DatabaseSchemaInput
	if err := json.Unmarshal(registrySchemaJSON, &schema); err != nil {
		return nil, fmt.Errorf("decode embedded registry schema: %w", err)
	}
	return &schema, nil
}

func registryDDL() ([]string, error) {
	var ddl []string
	if err := json.Unmarshal(registryDDLJSON, &ddl); err != nil {
		return nil, fmt.Errorf("decode embedded registry ddl: %w", err)
	}
	return ddl, nil
}

// SeedOpenschemaRegistry provisions (idempotently) the openschema client_database
// and converges its schema, then seeds the featured catalog rows if missing. Safe
// to run on every boot: provisioning is IF NOT EXISTS, DDL is OVERWRITE, the
// registry rows are replaced, and catalog rows are created only when absent.
func (r *Resolver) SeedOpenschemaRegistry(ctx context.Context) error {
	mr := &mutationResolver{r}
	schema, err := registrySchema()
	if err != nil {
		return err
	}
	tables, err := rewriteSchemaInput(schema)
	if err != nil {
		return fmt.Errorf("registry schema: %w", err)
	}
	ddl, err := registryDDL()
	if err != nil {
		return err
	}

	clientRef := models.NewRecordID("client", openschemaClientID)
	rec, err := mr.getClientDatabase(ctx, clientRef, openschemaRegistryDB)
	if errors.Is(err, database.ErrNotFound) {
		namespace, dbName, _, perr := r.store.ProvisionClientDatabase(ctx, openschemaClientID, openschemaRegistryDB)
		if perr != nil {
			return fmt.Errorf("provision database: %w", perr)
		}
		if _, cerr := surrealdb.Query[[]oauth.ClientDatabase](ctx, r.store.DB, `
			CREATE client_database SET
				client        = $client,
				name          = $name,
				namespace     = $namespace,
				db_name       = $db_name,
				schema_def    = $schema_def,
				schema_source = $schema_source
		`, map[string]any{
			"client":        clientRef,
			"name":          openschemaRegistryDB,
			"namespace":     namespace,
			"db_name":       dbName,
			"schema_def":    schema,
			"schema_source": registrySchemaSource,
		}); cerr != nil {
			return fmt.Errorf("record database: %w", cerr)
		}
		rec, err = mr.getClientDatabase(ctx, clientRef, openschemaRegistryDB)
	}
	if err != nil {
		return fmt.Errorf("lookup registry database: %w", err)
	}

	if derr := r.store.ApplyDDLToClientDB(ctx, rec.Namespace, rec.DbName, ddl); derr != nil {
		return fmt.Errorf("apply registry ddl: %w", derr)
	}
	if rerr := mr.recordClientTables(ctx, rec.ID, schema, tables); rerr != nil {
		return fmt.Errorf("record registry tables: %w", rerr)
	}
	if r.engine != nil {
		r.engine.Invalidate(openschemaClientID, openschemaRegistryDB)
	}

	return r.seedRegistryCatalog(ctx, rec.Namespace, rec.DbName)
}

// asInt coerces a SurrealDB numeric (int64/float64/uint64/int) to int.
func asInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case uint64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}

// versionRecordSuffix turns a semver into a record-id-safe suffix ("2.4.1" -> "2_4_1").
func versionRecordSuffix(v string) string {
	return strings.NewReplacer(".", "_", "-", "_", "+", "_").Replace(v)
}

func (r *Resolver) seedRegistryCatalog(ctx context.Context, namespace, dbName string) error {
	for _, s := range openschemaSeedCatalog() {
		rows, err := r.store.QueryClientDB(ctx, namespace, dbName,
			"SELECT count() AS c FROM schema WHERE scope = $scope AND name = $name GROUP ALL",
			map[string]any{"scope": s.scope, "name": s.name})
		if err != nil {
			return fmt.Errorf("check schema %s/%s: %w", s.scope, s.name, err)
		}
		// count()...GROUP ALL returns [{c: 0}] even when empty, so check the value.
		if len(rows) > 0 && asInt(rows[0]["c"]) > 0 {
			continue // already seeded
		}

		schemaID := s.scope + "_" + s.name
		if _, err := r.store.QueryClientDB(ctx, namespace, dbName, `
			CREATE type::record('schema', $id) SET
				scope = $scope, name = $name, description = $description,
				tags = $tags, license = 'MIT',
				repository = $repository, latest_version = $version,
				official = $official, downloads_total = $downloads
		`, map[string]any{
			"id": schemaID, "scope": s.scope, "name": s.name, "description": s.description,
			"tags": s.tags, "repository": "https://github.com/neoworks-io/" + s.name,
			"version": s.version, "official": s.official, "downloads": s.downloads,
		}); err != nil {
			return fmt.Errorf("seed schema %s: %w", schemaID, err)
		}

		versionID := schemaID + "_" + versionRecordSuffix(s.version)
		if _, err := r.store.QueryClientDB(ctx, namespace, dbName, `
			CREATE type::record('schema_version', $id) SET
				schema_id = $schema_id, version = $version, state = 'released',
				readme = $readme, targets = $targets, released_at = time::now()
		`, map[string]any{
			"id": versionID, "schema_id": schemaID, "version": s.version,
			"readme": s.readme, "targets": openschemaTargets,
		}); err != nil {
			return fmt.Errorf("seed version %s: %w", versionID, err)
		}

		for ordinal, file := range s.files {
			if _, err := r.store.QueryClientDB(ctx, namespace, dbName, `
				CREATE schema_file SET
					version_id = $version_id, path = $path, contents = $contents,
					size = $size, ordinal = $ordinal
			`, map[string]any{
				"version_id": versionID, "path": file.path, "contents": file.contents,
				"size": len(file.contents), "ordinal": ordinal,
			}); err != nil {
				return fmt.Errorf("seed file %s/%s: %w", versionID, file.path, err)
			}
		}
	}
	return nil
}
