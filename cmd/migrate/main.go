package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/joho/godotenv"
	"github.com/neoworks/auth/storage/migrations"
	surrealdb "github.com/surrealdb/surrealdb.go"
)

func main() {
	_ = godotenv.Load(".env")

	url := env("SURREAL_URL", "ws://127.0.0.1:8000")
	user := env("SURREAL_USER", "root")
	pass := env("SURREAL_PASS", "root")
	namespace := env("SURREAL_NS", "neoworks")
	database := env("SURREAL_DB", "auth")
	dir := env("MIGRATIONS_DIR", "./sql/migrations")

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
	if err := conn.Use(ctx, namespace, database); err != nil {
		slog.Error("use db", "err", err)
		os.Exit(1)
	}

	applied, err := migrations.Apply(ctx, conn, dir, func(migration migrations.Migration) {
		slog.Info("applied", "version", migration.Version, "name", migration.Name)
	})
	if err != nil {
		slog.Error("migration failed", "err", err)
		os.Exit(1)
	}
	if len(applied) == 0 {
		slog.Info("no pending migrations")
		return
	}
	slog.Info("done", "applied", len(applied))
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
