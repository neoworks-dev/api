// Package dbtest gives tests a fresh, fully migrated SurrealDB database backed
// by a throwaway in-memory server process.
package dbtest

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/migrations"
	surrealdb "github.com/surrealdb/surrealdb.go"
)

const (
	rootUser = "root"
	rootPass = "root"
)

var (
	serverOnce    sync.Once
	serverURL     string
	serverStartup error
)

// New returns a store on a new database inside the shared in-memory server with
// all migrations applied. The test is skipped when no surreal binary is on PATH.
func New(t *testing.T) *database.SurrealStore {
	t.Helper()
	if _, err := exec.LookPath("surreal"); err != nil {
		t.Skip("surreal binary not on PATH")
	}
	serverOnce.Do(startServer)
	if serverStartup != nil {
		t.Fatalf("start surreal: %v", serverStartup)
	}

	databaseName := "t" + uuid.NewString()[:8]
	store, err := database.NewSurrealStore(serverURL, rootUser, rootPass, "test", databaseName)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := migrations.Apply(context.Background(), store.DB, migrationsDir(), nil); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return store
}

func migrationsDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "sql", "migrations")
}

func startServer() {
	address, err := freeAddress()
	if err != nil {
		serverStartup = err
		return
	}
	command := exec.Command("surreal", "start", "--log", "error",
		"--user", rootUser, "--pass", rootPass, "--bind", address, "memory")
	configureChild(command)
	if err := command.Start(); err != nil {
		serverStartup = err
		return
	}
	serverURL = "ws://" + address
	serverStartup = waitReady(serverURL)
}

func freeAddress() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer listener.Close()
	return listener.Addr().String(), nil
}

func waitReady(url string) error {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := surrealdb.FromEndpointURLString(context.Background(), url)
		if err == nil {
			connection.Close(context.Background())
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("surreal did not become ready at %s", url)
}
