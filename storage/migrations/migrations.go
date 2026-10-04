// Package migrations applies the numbered SurrealQL files in sql/migrations.
package migrations

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	surrealdb "github.com/surrealdb/surrealdb.go"
)

const initSQL = `
DEFINE TABLE IF NOT EXISTS _migration SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS version    ON _migration TYPE int      READONLY;
DEFINE FIELD IF NOT EXISTS name       ON _migration TYPE string   READONLY;
DEFINE FIELD IF NOT EXISTS applied_at ON _migration TYPE datetime VALUE time::now() READONLY;
DEFINE INDEX IF NOT EXISTS idx_migration_version ON _migration FIELDS version UNIQUE;
`

type Migration struct {
	Version int
	Name    string
	Path    string
}

type appliedRecord struct {
	Version int `json:"version"`
}

// Apply runs every migration in dir that is not yet recorded, in version order,
// and returns the ones it applied. Each file runs in its own transaction.
func Apply(ctx context.Context, conn *surrealdb.DB, dir string, onApplied func(Migration)) ([]Migration, error) {
	if _, err := surrealdb.Query[[]any](ctx, conn, initSQL, nil); err != nil {
		return nil, fmt.Errorf("init migration table: %w", err)
	}
	applied, err := appliedVersions(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("query applied migrations: %w", err)
	}
	pending, err := Pending(dir, applied)
	if err != nil {
		return nil, fmt.Errorf("scan migrations dir: %w", err)
	}
	for index, migration := range pending {
		if err := apply(ctx, conn, migration); err != nil {
			return pending[:index], fmt.Errorf("migration %d %s: %w", migration.Version, migration.Name, err)
		}
		if onApplied != nil {
			onApplied(migration)
		}
	}
	return pending, nil
}

func appliedVersions(ctx context.Context, conn *surrealdb.DB) (map[int]bool, error) {
	results, err := surrealdb.Query[[]appliedRecord](ctx, conn,
		"SELECT version FROM _migration ORDER BY version ASC", nil,
	)
	if err != nil {
		return nil, err
	}
	versions := map[int]bool{}
	for _, queryResult := range *results {
		for _, record := range queryResult.Result {
			versions[record.Version] = true
		}
	}
	return versions, nil
}

// Pending lists the migration files in dir whose version is not in applied.
func Pending(dir string, applied map[int]bool) ([]Migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var pending []Migration
	for _, entry := range entries {
		migration, ok := parseFileName(dir, entry.Name())
		if !ok || entry.IsDir() || applied[migration.Version] {
			continue
		}
		pending = append(pending, migration)
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].Version < pending[j].Version })
	return pending, nil
}

func parseFileName(dir, fileName string) (Migration, bool) {
	if !strings.HasSuffix(fileName, ".surql") {
		return Migration{}, false
	}
	parts := strings.SplitN(fileName, "_", 2)
	if len(parts) != 2 {
		return Migration{}, false
	}
	version, err := strconv.Atoi(parts[0])
	if err != nil {
		return Migration{}, false
	}
	return Migration{
		Version: version,
		Name:    strings.TrimSuffix(parts[1], ".surql"),
		Path:    filepath.Join(dir, fileName),
	}, true
}

func apply(ctx context.Context, conn *surrealdb.DB, migration Migration) error {
	statements, err := os.ReadFile(migration.Path)
	if err != nil {
		return err
	}

	wrapped := fmt.Sprintf("BEGIN TRANSACTION;\n%s\nCOMMIT TRANSACTION;", statements)
	if _, err := surrealdb.Query[[]any](ctx, conn, wrapped, nil); err != nil {
		return err
	}

	_, err = surrealdb.Query[[]any](ctx, conn,
		"CREATE _migration SET version = $version, name = $name",
		map[string]any{"version": migration.Version, "name": migration.Name},
	)
	return err
}
