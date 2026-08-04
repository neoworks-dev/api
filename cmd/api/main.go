package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
	"github.com/neoworks/auth/config"
	"github.com/neoworks/auth/crypto"
	"github.com/neoworks/auth/dataplane"
	"github.com/neoworks/auth/email"
	"github.com/neoworks/auth/embeddings"
	"github.com/neoworks/auth/gql"
	resolvers "github.com/neoworks/auth/gql/resolvers"
	approvalhandlers "github.com/neoworks/auth/handlers/approvals"
	filehandlers "github.com/neoworks/auth/handlers/file"
	spacehandlers "github.com/neoworks/auth/handlers/spaces"
	keyhandlers "github.com/neoworks/auth/handlers/keys"
	linkpreviewhandlers "github.com/neoworks/auth/handlers/linkpreview"
	molliehandlers "github.com/neoworks/auth/handlers/mollie"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/mollie"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/publicerr"
	"github.com/neoworks/auth/push"
	"github.com/neoworks/auth/scheduler"
	"github.com/neoworks/auth/storage/cache"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/objectstore"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func main() {
	_ = godotenv.Load(".env")
	setupLogger()

	slog.Info("Starting api server")

	// ── Config ────────────────────────────────────────────────────────────────
	keyPath := env("KEY_PATH", "./keys/auth.pem")
	surrealURL := env("SURREAL_URL", "ws://127.0.0.1:8000")
	surrealUser := env("SURREAL_USER", "root")
	surrealPass := env("SURREAL_PASS", "root")
	surrealNS := env("SURREAL_NS", "neoworks")
	surrealDB := env("SURREAL_DB", "auth")
	issuerURL := env("ISSUER_URL", config.ServiceURL("oauth"))
	port := env("PORT", "8081")
	s3Endpoint := stripScheme(env("S3_ENDPOINT", "127.0.0.1:9000"))
	s3AccessKey := env("S3_ACCESS_KEY_ID", "minioadmin")
	s3SecretKey := env("S3_SECRET_ACCESS_KEY", "minioadmin")
	s3Bucket := env("S3_BUCKET_PRIVATE", "neoworks-private")
	s3UseSSL := hasScheme(env("S3_ENDPOINT", ""), "https")

	// ── Keys ──────────────────────────────────────────────────────────────────
	keys, err := crypto.NewKeyManager(keyPath)
	if err != nil {
		log.Fatalf("key manager: %v", err)
	}

	// ── Storage ───────────────────────────────────────────────────────────────
	redis := cache.NewRedisStore(cache.ConfigFromEnv())

	surreal, err := database.NewSurrealStore(
		surrealURL, surrealUser, surrealPass, surrealNS, surrealDB,
	)
	if err != nil {
		log.Fatalf("surrealdb: %v", err)
	}

	// Free-plan orgs share one SurrealDB instance, isolated by their per-client
	// namespace (client_{clientID}); pro-plan orgs get a dedicated database
	// (provisioned separately — not wired here yet). The shared instance defaults to
	// the control-plane connection; point it at a separate instance in production.
	if sharedURL := os.Getenv("SHARED_TENANT_SURREAL_URL"); sharedURL != "" {
		surreal.UseSharedTenant(
			sharedURL,
			env("SHARED_TENANT_SURREAL_USER", "root"),
			env("SHARED_TENANT_SURREAL_PASS", "root"),
		)
		slog.Info("shared tenant instance configured", "endpoint", sharedURL)
	} else {
		slog.Info("shared tenant instance defaulting to control-plane connection")
	}

	// Per-tenant query admission control on the shared instance: caps concurrent
	// queries per tenant (and globally) via Redis so a noisy neighbour queues rather
	// than starving the others.
	surreal.UseThrottler(database.NewRedisThrottler(redis.Client(), database.ThrottleConfigFromEnv()))

	// Sample per-database query metrics into the usage time-series on an interval.
	surreal.StartInstanceMetering(context.Background(), time.Minute)

	objects, err := objectstore.New(s3Endpoint, s3AccessKey, s3SecretKey, s3Bucket, s3UseSSL)
	if err != nil {
		log.Fatalf("objectstore: %v", err)
	}
	if err := objects.EnsureBucket(context.Background()); err != nil {
		log.Fatalf("objectstore bucket: %v", err)
	}

	// ── Core ──────────────────────────────────────────────────────────────────
	issuer := oauth.NewTokenIssuer(keys.PrivateKey(), issuerURL)
	pushSender := push.NewSender(push.ConfigFromEnv())

	// Background jobs: fire calendar reminders as notifications.
	scheduler.NewReminderScheduler(surreal, pushSender).Start(context.Background())

	// Background job: purge expired space-item tombstones and advance purge horizons.
	scheduler.NewSpacePurgeScheduler(surreal).Start(context.Background())

	// ── Middleware ────────────────────────────────────────────────────────────
	clientAuth := middleware.NewJWTMiddleware(issuer, redis)

	// ── Router ────────────────────────────────────────────────────────────────
	router := chi.NewRouter()
	router.Use(chimiddleware.Logger)
	router.Use(chimiddleware.Recoverer)
	router.Use(chimiddleware.RealIP)
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			// Custom response headers the browser must be allowed to read cross-origin
			// (the single-shot thumbnail carries its wrapped DEK here).
			w.Header().Set("Access-Control-Expose-Headers", "X-Wrapped-DEK, X-File-Mime, X-File-Scope")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	mailer := email.NewSender(email.ConfigFromEnv())
	dataEngine := dataplane.NewEngine(surreal)
	embedder := embeddings.NewClient(embeddings.ConfigFromEnv())
	mollieClient := mollie.NewClient(mollie.ConfigFromEnv())
	resolver := resolvers.NewGqlResolver(surreal, mailer, pushSender, dataEngine, embedder, mollieClient)

	// Provision the OpenSchema public registry's client database + seed its
	// catalog (idempotent). Non-fatal: a transient DB hiccup must not block boot.
	if err := resolver.SeedOpenschemaRegistry(context.Background()); err != nil {
		slog.Error("seed openschema registry", "error", err)
	}

	// Background job: embed memory chunks the synchronous path could not, retry
	// failures, and re-embed chunks stale after a model-tier change.
	scheduler.NewEmbedBackfillScheduler(surreal, embedder).Start(context.Background())
	srv := handler.NewDefaultServer(
		gql.NewExecutableSchema(gql.Config{Resolvers: resolver}),
	)

	// Default-deny error exposure: only errors explicitly marked Public reach the
	// client. Everything else is logged server-side and returned as a generic
	// message so internal details (DB schema, record ids) never leak.
	srv.SetErrorPresenter(func(ctx context.Context, e error) *gqlerror.Error {
		gqlErr := graphql.DefaultErrorPresenter(ctx, e)
		if msg, ok := resolvers.AsPublic(e); ok {
			gqlErr.Message = msg
			return gqlErr
		}
		// Surface a sanitized reason for known query-shape DB failures; the full
		// error is still logged server-side and unrecognized errors stay generic.
		if msg, ok := publicerr.ClassifyDBError(e); ok {
			slog.Error("graphql error", "error", e, "path", gqlErr.Path)
			gqlErr.Message = msg
			return gqlErr
		}
		slog.Error("graphql error", "error", e, "path", gqlErr.Path)
		gqlErr.Message = "Internal server error"
		return gqlErr
	})

	// Liveness/readiness probe. Boot-blocking dependencies (key manager, SurrealDB,
	// object store) are validated before the server starts serving, so a plain 200
	// here means the process is ready to take traffic.
	router.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Key management — public endpoints (no auth)
	keysHandler := keyhandlers.NewHandler(surreal, redis)
	keysHandler.RegisterPublic(router)

	// Mollie payment webhook — public (Mollie calls it server-to-server; the
	// handler authenticates by fetching the referenced payment from Mollie).
	molliehandlers.NewHandler(surreal, mollieClient).RegisterPublic(router)

	// Per-database data plane: schema introspection is public; data operations
	// authenticate inside the handler (bearer + tenant match).
	router.Handle("/graphql/db/{clientId}/{dbName}", middleware.Batch(dataEngine.Handler(clientAuth)))

	// Protected endpoints — require client auth
	router.Group(func(r chi.Router) {
		r.Use(clientAuth.JWTMiddleware)
		r.Handle("/graphql", middleware.Batch(srv))
		keysHandler.RegisterAuthenticated(r)
		approvalhandlers.NewHandler(surreal, redis, pushSender).RegisterAuthenticated(r)
		filehandlers.NewHandler(surreal, objects).Register(r)
		spacehandlers.NewHandler(surreal).Register(r)
		linkpreviewhandlers.NewHandler().Register(r)
	})

	router.Handle("/playground", playground.Handler("NeoWorks API", "/graphql"))

	// Graceful shutdown: on SIGTERM (pod eviction, rollout, HPA scale-down) stop
	// accepting new connections and let in-flight OAuth/GraphQL requests drain
	// before the process exits, instead of dropping them mid-flight.
	httpServer := &http.Server{Addr: ":" + port, Handler: router}
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	shutdownSignal, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-shutdownSignal.Done()

	slog.Info("shutdown signal received; draining in-flight requests")
	drainCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(drainCtx); err != nil {
		slog.Error("graceful shutdown", "error", err)
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// stripScheme removes a leading http:// or https:// from an endpoint string.
func stripScheme(s string) string {
	for _, prefix := range []string{"https://", "http://"} {
		if len(s) > len(prefix) && s[:len(prefix)] == prefix {
			return s[len(prefix):]
		}
	}
	return s
}

func hasScheme(s, scheme string) bool {
	prefix := scheme + "://"
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
