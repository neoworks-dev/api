// Package migrations applies the numbered SurrealQL files in sql/migrations.
//
// Each applied file is recorded with its SHA-256. A file that changes after it
// was applied stops every run until the change is undone or the database is
// reset: an edited migration never reaches a database that already ran it, so
// the database would silently drift from the files.
package migrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
DEFINE FIELD IF NOT EXISTS checksum   ON _migration TYPE option<string>;
DEFINE INDEX IF NOT EXISTS idx_migration_version ON _migration FIELDS version UNIQUE;
`

// ErrChanged means a migration file differs from the one the database applied.
var ErrChanged = errors.New("applied migration changed")

type Migration struct {
	Version  int
	Name     string
	Path     string
	Checksum string
}

type appliedRecord struct {
	Version  int    `json:"version"`
	Checksum string `json:"checksum,omitempty"`
}

// Apply runs every migration in dir that is not yet recorded, in version order,
// and returns the ones it applied. Each file runs in its own transaction. It
// applies nothing when an already applied file has changed.
func Apply(ctx context.Context, conn *surrealdb.DB, dir string, onApplied func(Migration)) ([]Migration, error) {
	if _, err := surrealdb.Query[[]any](ctx, conn, initSQL, nil); err != nil {
		return nil, fmt.Errorf("init migration table: %w", err)
	}
	applied, err := appliedRecords(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("query applied migrations: %w", err)
	}
	files, err := Scan(dir)
	if err != nil {
		return nil, fmt.Errorf("scan migrations dir: %w", err)
	}
	if err := verifyApplied(ctx, conn, files, applied); err != nil {
		return nil, err
	}
	pending := notApplied(files, applied)
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

func appliedRecords(ctx context.Context, conn *surrealdb.DB) (map[int]appliedRecord, error) {
	results, err := surrealdb.Query[[]appliedRecord](ctx, conn,
		"SELECT version, checksum FROM _migration ORDER BY version ASC", nil,
	)
	if err != nil {
		return nil, err
	}
	records := map[int]appliedRecord{}
	for _, queryResult := range *results {
		for _, record := range queryResult.Result {
			records[record.Version] = record
		}
	}
	return records, nil
}

// verifyApplied compares every applied file with its recorded checksum.
func verifyApplied(ctx context.Context, conn *surrealdb.DB, files []Migration, applied map[int]appliedRecord) error {
	var changed []string
	for _, migration := range files {
		record, found := applied[migration.Version]
		if !found {
			continue
		}
		matches, err := matchesRecord(ctx, conn, migration, record)
		if err != nil {
			return fmt.Errorf("record checksum of migration %d: %w", migration.Version, err)
		}
		if !matches {
			changed = append(changed, filepath.Base(migration.Path))
		}
	}
	if len(changed) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s changed after this database applied it. "+
		"Undo the edit and put the change in a new migration, or reset the database", ErrChanged, strings.Join(changed, ", "))
}

// matchesRecord reports whether the file is the one the database applied. A
// record from before checksums existed takes the file's current checksum.
func matchesRecord(ctx context.Context, conn *surrealdb.DB, migration Migration, record appliedRecord) (bool, error) {
	if record.Checksum == "" {
		return true, recordChecksum(ctx, conn, migration)
	}
	return record.Checksum == migration.Checksum, nil
}

func recordChecksum(ctx context.Context, conn *surrealdb.DB, migration Migration) error {
	_, err := surrealdb.Query[[]any](ctx, conn,
		"UPDATE _migration SET checksum = $checksum WHERE version = $version",
		map[string]any{"version": migration.Version, "checksum": migration.Checksum},
	)
	return err
}

func notApplied(files []Migration, applied map[int]appliedRecord) []Migration {
	var pending []Migration
	for _, migration := range files {
		if _, found := applied[migration.Version]; !found {
			pending = append(pending, migration)
		}
	}
	return pending
}

// Scan lists the migration files in dir in version order, with their checksums.
func Scan(dir string) ([]Migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []Migration
	for _, entry := range entries {
		migration, ok := parseFileName(dir, entry.Name())
		if !ok || entry.IsDir() {
			continue
		}
		migration.Checksum, err = checksumOf(migration.Path)
		if err != nil {
			return nil, err
		}
		files = append(files, migration)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Version < files[j].Version })
	return files, nil
}

func checksumOf(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]), nil
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
		"CREATE _migration SET version = $version, name = $name, checksum = $checksum",
		map[string]any{"version": migration.Version, "name": migration.Name, "checksum": migration.Checksum},
	)
	return err
}
