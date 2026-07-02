// Command seed-openschema provisions the OpenSchema registry client database and
// seeds its catalog by invoking the same code path the API runs at boot. Useful
// to (re)seed without restarting the API. Idempotent.
package main

import (
	"context"
	"log"

	"github.com/joho/godotenv"
	"github.com/neoworks/auth/dataplane"
	resolvers "github.com/neoworks/auth/gql/resolvers"
	"github.com/neoworks/auth/storage/database"
	"os"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	_ = godotenv.Load(".env")

	store, err := database.NewSurrealStore(
		env("SURREAL_URL", "ws://127.0.0.1:8000"),
		env("SURREAL_USER", "root"),
		env("SURREAL_PASS", "root"),
		env("SURREAL_NS", "neoworks"),
		env("SURREAL_DB", "auth"),
	)
	if err != nil {
		log.Fatalf("surrealdb: %v", err)
	}

	engine := dataplane.NewEngine(store)
	resolver := resolvers.NewGqlResolver(store, nil, nil, engine, nil)

	if err := resolver.SeedOpenschemaRegistry(context.Background()); err != nil {
		log.Fatalf("seed: %v", err)
	}
	log.Println("openschema registry provisioned + seeded")
}
