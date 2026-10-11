package migrations_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neoworks/auth/storage/database/dbtest"
	"github.com/neoworks/auth/storage/migrations"
	surrealdb "github.com/surrealdb/surrealdb.go"
)

func writeMigration(t *testing.T, dir, fileName, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func apply(t *testing.T, conn *surrealdb.DB, dir string) ([]migrations.Migration, error) {
	t.Helper()
	return migrations.Apply(context.Background(), conn, dir, nil)
}

func TestAnUnchangedHistoryAppliesOnlyNewFiles(t *testing.T) {
	conn := dbtest.Empty(t).DB
	dir := t.TempDir()
	writeMigration(t, dir, "001_first.surql", "DEFINE TABLE first SCHEMALESS;")
	if _, err := apply(t, conn, dir); err != nil {
		t.Fatal(err)
	}
	writeMigration(t, dir, "002_second.surql", "DEFINE TABLE second SCHEMALESS;")

	applied, err := apply(t, conn, dir)

	if err != nil || len(applied) != 1 || applied[0].Version != 2 {
		t.Fatalf("applied %+v, %v; want only migration 2", applied, err)
	}
}

func TestAnEditedAppliedMigrationStopsEveryRun(t *testing.T) {
	conn := dbtest.Empty(t).DB
	dir := t.TempDir()
	writeMigration(t, dir, "001_first.surql", "DEFINE TABLE first SCHEMALESS;")
	if _, err := apply(t, conn, dir); err != nil {
		t.Fatal(err)
	}
	writeMigration(t, dir, "001_first.surql", "DEFINE TABLE first SCHEMAFULL;")
	writeMigration(t, dir, "002_second.surql", "DEFINE TABLE second SCHEMALESS;")

	applied, err := apply(t, conn, dir)

	if !errors.Is(err, migrations.ErrChanged) || !strings.Contains(err.Error(), "001_first.surql") {
		t.Fatalf("err = %v, want ErrChanged naming 001_first.surql", err)
	}
	if len(applied) != 0 {
		t.Fatalf("applied %+v despite the edit", applied)
	}
}

func TestUndoingTheEditLetsRunsContinue(t *testing.T) {
	conn := dbtest.Empty(t).DB
	dir := t.TempDir()
	original := "DEFINE TABLE first SCHEMALESS;"
	writeMigration(t, dir, "001_first.surql", original)
	if _, err := apply(t, conn, dir); err != nil {
		t.Fatal(err)
	}
	writeMigration(t, dir, "001_first.surql", "DEFINE TABLE first SCHEMAFULL;")
	if _, err := apply(t, conn, dir); !errors.Is(err, migrations.ErrChanged) {
		t.Fatalf("err = %v, want ErrChanged", err)
	}
	writeMigration(t, dir, "001_first.surql", original)

	if _, err := apply(t, conn, dir); err != nil {
		t.Fatalf("after undoing the edit: %v", err)
	}
}

func TestRecordsFromBeforeChecksumsAdoptTheCurrentFile(t *testing.T) {
	conn := dbtest.Empty(t).DB
	dir := t.TempDir()
	writeMigration(t, dir, "001_first.surql", "DEFINE TABLE first SCHEMALESS;")
	if _, err := apply(t, conn, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := surrealdb.Query[[]any](context.Background(), conn, "UPDATE _migration SET checksum = NONE", nil); err != nil {
		t.Fatal(err)
	}

	if _, err := apply(t, conn, dir); err != nil {
		t.Fatalf("first run after the upgrade: %v", err)
	}
	writeMigration(t, dir, "001_first.surql", "DEFINE TABLE first SCHEMAFULL;")
	if _, err := apply(t, conn, dir); !errors.Is(err, migrations.ErrChanged) {
		t.Fatalf("an edit after adopting the checksum: err = %v, want ErrChanged", err)
	}
}
