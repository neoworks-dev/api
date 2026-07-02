package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
	surrealdb "github.com/surrealdb/surrealdb.go"
)

const initSQL = `
DEFINE TABLE IF NOT EXISTS _migration SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS version    ON _migration TYPE int      READONLY;
DEFINE FIELD IF NOT EXISTS name       ON _migration TYPE string   READONLY;
DEFINE FIELD IF NOT EXISTS applied_at ON _migration TYPE datetime VALUE time::now() READONLY;
DEFINE INDEX IF NOT EXISTS idx_migration_version ON _migration FIELDS version UNIQUE;
`

type migrationRecord struct {
	Version int `json:"version"`
}

type migration struct {
	version int
	name    string
	path    string
}

func main() {
	_ = godotenv.Load(".env")

	url  := env("SURREAL_URL", "ws://127.0.0.1:8000")
	user := env("SURREAL_USER", "root")
	pass := env("SURREAL_PASS", "root")
	ns   := env("SURREAL_NS", "neoworks")
	db   := env("SURREAL_DB", "auth")
	dir  := env("MIGRATIONS_DIR", "./sql/migrations")

	ctx := context.Background()

	conn, err := surrealdb.FromEndpointURLString(ctx, url)
	if err != nil {
		slog.Error("connect", "err", err)
		os.Exit(1)
	}

	if _, err := conn.SignIn(ctx, surrealdb.Auth{Username: user, Password: pass}); err != nil {
		slog.Error("sign in", "err", err)
		os.Exit(1)
	}

	if err := conn.Use(ctx, ns, db); err != nil {
		slog.Error("use db", "err", err)
		os.Exit(1)
	}

	if _, err := surrealdb.Query[[]any](ctx, conn, initSQL, nil); err != nil {
		slog.Error("init migration table", "err", err)
		os.Exit(1)
	}

	applied, err := appliedVersions(ctx, conn)
	if err != nil {
		slog.Error("query applied migrations", "err", err)
		os.Exit(1)
	}

	pending, err := pendingMigrations(dir, applied)
	if err != nil {
		slog.Error("scan migrations dir", "err", err)
		os.Exit(1)
	}

	if len(pending) == 0 {
		slog.Info("no pending migrations")
		return
	}

	for _, m := range pending {
		if err := apply(ctx, conn, m); err != nil {
			slog.Error("migration failed", "version", m.version, "name", m.name, "err", err)
			os.Exit(1)
		}
		slog.Info("applied", "version", m.version, "name", m.name)
	}

	slog.Info("done", "applied", len(pending))
}

func appliedVersions(ctx context.Context, conn *surrealdb.DB) (map[int]bool, error) {
	results, err := surrealdb.Query[[]migrationRecord](ctx, conn,
		"SELECT version FROM _migration ORDER BY version ASC", nil,
	)
	if err != nil {
		return nil, err
	}
	out := map[int]bool{}
	for _, qr := range *results {
		for _, r := range qr.Result {
			out[r.Version] = true
		}
	}
	return out, nil
}

func pendingMigrations(dir string, applied map[int]bool) ([]migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var migrations []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".surql") {
			continue
		}
		parts := strings.SplitN(e.Name(), "_", 2)
		if len(parts) != 2 {
			continue
		}
		v, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		if applied[v] {
			continue
		}
		migrations = append(migrations, migration{
			version: v,
			name:    strings.TrimSuffix(parts[1], ".surql"),
			path:    filepath.Join(dir, e.Name()),
		})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })
	return migrations, nil
}

func apply(ctx context.Context, conn *surrealdb.DB, m migration) error {
	sql, err := os.ReadFile(m.path)
	if err != nil {
		return err
	}

	wrapped := fmt.Sprintf("BEGIN TRANSACTION;\n%s\nCOMMIT TRANSACTION;", sql)
	if _, err := surrealdb.Query[[]any](ctx, conn, wrapped, nil); err != nil {
		return err
	}

	_, err = surrealdb.Query[[]any](ctx, conn,
		"CREATE _migration SET version = $version, name = $name",
		map[string]any{"version": m.version, "name": m.name},
	)
	return err
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
