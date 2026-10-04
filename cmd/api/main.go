package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
	"github.com/neoworks/auth/config"
	"github.com/neoworks/auth/crypto"
	approvalhandlers "github.com/neoworks/auth/handlers/approvals"
	assethandlers "github.com/neoworks/auth/handlers/assets"
	blobhandlers "github.com/neoworks/auth/handlers/blobs"
	devicehandlers "github.com/neoworks/auth/handlers/devices"
	installhandlers "github.com/neoworks/auth/handlers/installs"
	keyhandlers "github.com/neoworks/auth/handlers/keys"
	nodehandlers "github.com/neoworks/auth/handlers/nodes"
	notificationhandlers "github.com/neoworks/auth/handlers/notifications"
	renewalhandlers "github.com/neoworks/auth/handlers/renewal"
	settinghandlers "github.com/neoworks/auth/handlers/settings"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/push"
	"github.com/neoworks/auth/scheduler"
	"github.com/neoworks/auth/storage/cache"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/objectstore"
)

const (
	defaultStorageQuotaBytes = 10 << 30
	shutdownTimeout          = 25 * time.Second
)

func main() {
	_ = godotenv.Load(".env")
	setupLogger()

	slog.Info("Starting api server")

	keys, err := crypto.NewKeyManager(env("KEY_PATH", "./keys/auth.pem"))
	if err != nil {
		log.Fatalf("key manager: %v", err)
	}

	redis := cache.NewRedisStore(cache.ConfigFromEnv())
	surreal := connectSurreal()
	objects := connectObjectStore()

	issuer := oauth.NewTokenIssuer(keys.PrivateKey(), env("ISSUER_URL", config.ServiceURL("oauth")))
	clientAuth := middleware.NewJWTMiddleware(issuer, redis)

	scheduler.NewTombstonePurger(surreal, objects, tombstoneRetention()).Start(context.Background())

	servers := []*http.Server{
		{Addr: ":" + env("PORT", "8081"), Handler: apiRouter(surreal, redis, objects, clientAuth)},
		{Addr: ":" + env("ASSETS_PORT", "8082"), Handler: assethandlers.NewHandler(surreal, redis, objects, clientAuth).Router()},
	}
	for _, server := range servers {
		go listen(server)
	}
	waitForShutdown(servers)
}

func connectSurreal() *database.SurrealStore {
	surreal, err := database.NewSurrealStore(
		env("SURREAL_URL", "ws://127.0.0.1:8000"),
		env("SURREAL_USER", "root"),
		env("SURREAL_PASS", "root"),
		env("SURREAL_NS", "neoworks"),
		env("SURREAL_DB", "auth"),
	)
	if err != nil {
		log.Fatalf("surrealdb: %v", err)
	}
	return surreal
}

func connectObjectStore() *objectstore.Store {
	endpoint := env("S3_ENDPOINT", "127.0.0.1:9000")
	accessKey := env("S3_ACCESS_KEY_ID", "minioadmin")
	secretKey := env("S3_SECRET_ACCESS_KEY", "minioadmin")

	objects, err := objectstore.New(stripScheme(endpoint), accessKey, secretKey,
		env("S3_BUCKET_PRIVATE", "neoworks-private"), hasScheme(endpoint, "https"))
	if err != nil {
		log.Fatalf("objectstore: %v", err)
	}
	if err := objects.EnsureBucket(context.Background()); err != nil {
		log.Fatalf("objectstore bucket: %v", err)
	}

	publicEndpoint := env("S3_PUBLIC_ENDPOINT", endpoint)
	if err := objects.UsePublicEndpoint(stripScheme(publicEndpoint), accessKey, secretKey, hasScheme(publicEndpoint, "https")); err != nil {
		log.Fatalf("objectstore public endpoint: %v", err)
	}
	return objects
}

func tombstoneRetention() time.Duration {
	days, err := strconv.Atoi(os.Getenv("TOMBSTONE_RETENTION_DAYS"))
	if err != nil || days < 1 {
		return 0
	}
	return time.Duration(days) * 24 * time.Hour
}

func storageQuotaBytes() int64 {
	quota, err := strconv.ParseInt(os.Getenv("STORAGE_QUOTA_BYTES"), 10, 64)
	if err != nil {
		return defaultStorageQuotaBytes
	}
	return quota
}

func apiRouter(surreal *database.SurrealStore, redis *cache.RedisStore, objects *objectstore.Store, clientAuth *middleware.ClientAuth) http.Handler {
	router := chi.NewRouter()
	router.Use(chimiddleware.Logger)
	router.Use(chimiddleware.Recoverer)
	router.Use(chimiddleware.RealIP)
	router.Use(allowCrossOrigin)

	router.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	nodes := nodehandlers.NewHandler(surreal)
	blobs := blobhandlers.NewHandler(surreal, objects, storageQuotaBytes())
	nodes.RegisterPublic(router)
	blobs.RegisterPublic(router)

	router.Group(func(authenticated chi.Router) {
		authenticated.Use(clientAuth.JWTMiddleware)
		pushSender := push.NewSender(push.ConfigFromEnv())
		approvalhandlers.NewHandler(surreal, redis, pushSender).RegisterAuthenticated(authenticated)

		authenticated.Group(func(principals chi.Router) {
			principals.Use(middleware.PrincipalMiddleware(surreal))
			keyhandlers.NewHandler(surreal).RegisterAuthenticated(principals)
			devicehandlers.NewHandler(surreal).RegisterAuthenticated(principals)
			installhandlers.NewHandler(surreal).RegisterAuthenticated(principals)
			renewals := renewalhandlers.NewHandler(surreal)
			account := principals.With(middleware.RequireAccountPrincipal)
			renewals.RegisterAuthenticator(account.With(middleware.RequireClient(env("AUTHENTICATOR_CLIENT_ID", "neoworks-authenticator"))))
			data := principals.With(middleware.RequireDataAccess(env("VAULT_CLIENT_ID", "neoworks.vault")))
			nodes.RegisterAuthenticated(data)
			renewals.RegisterVerifier(data)
			blobs.RegisterAuthenticated(data)
			settinghandlers.NewHandler(surreal).RegisterAuthenticated(principals)
			notificationhandlers.NewHandler(surreal, pushSender).RegisterAuthenticated(principals)
		})
	})
	return router
}

func allowCrossOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, If-Match")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func listen(server *http.Server) {
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server %s: %v", server.Addr, err)
	}
}

// waitForShutdown drains in-flight requests on SIGTERM/SIGINT before exiting.
func waitForShutdown(servers []*http.Server) {
	shutdownSignal, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-shutdownSignal.Done()

	slog.Info("shutdown signal received; draining in-flight requests")
	drainContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, server := range servers {
		if err := server.Shutdown(drainContext); err != nil {
			slog.Error("graceful shutdown", "addr", server.Addr, "error", err)
		}
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// stripScheme removes a leading http:// or https:// from an endpoint string.
func stripScheme(endpoint string) string {
	for _, prefix := range []string{"https://", "http://"} {
		if len(endpoint) > len(prefix) && endpoint[:len(prefix)] == prefix {
			return endpoint[len(prefix):]
		}
	}
	return endpoint
}

func hasScheme(endpoint, scheme string) bool {
	prefix := scheme + "://"
	return len(endpoint) >= len(prefix) && endpoint[:len(prefix)] == prefix
}
