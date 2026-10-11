package storage_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/handlers/handlertest"
	"github.com/neoworks/auth/handlers/storage"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

type fixture struct {
	t      *testing.T
	store  *database.SurrealStore
	router *handlertest.Router
}

func newFixture(t *testing.T) *fixture {
	store := dbtest.New(t)
	handler := storage.NewHandler(store)
	router := handlertest.NewAuthenticated(func(router chi.Router) { handler.RegisterAuthenticated(router) })
	return &fixture{t: t, store: store, router: router}
}

func (f *fixture) authorize(userID string, clientID string) {
	f.t.Helper()
	_, err := surrealdb.Query[[]any](context.Background(), f.store.DB,
		"UPSERT grant SET user = $user, client = $client, scopes = [], enabled = true WHERE user = $user AND client = $client",
		map[string]any{"user": models.NewRecordID("user", userID), "client": models.NewRecordID("client", clientID)})
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) install(principal access.Principal, clientID string) access.Principal {
	f.t.Helper()
	installID := uuid.NewString()
	_, err := f.store.CreateInstall(context.Background(), database.CreateInstallParams{
		InstallID: installID, UserID: principal.UserID, ClientID: clientID, EncPub: "e", SignPub: "s", Name: "Phone",
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return access.Principal{UserID: principal.UserID, InstallID: installID, ClientID: clientID, Scopes: principal.Scopes}
}

func (f *fixture) usage(principal access.Principal) database.StorageUsage {
	f.t.Helper()
	response := f.router.Do(f.t, principal, "GET", "/api/v1/storage", nil, nil)
	if response.Code != http.StatusOK {
		f.t.Fatalf("storage: %d %s", response.Code, response.Body.String())
	}
	var usage database.StorageUsage
	handlertest.Decode(f.t, response, &usage)
	return usage
}

func TestTheAccountSeesEveryAuthorizedAppAndAnAppOnlyItself(t *testing.T) {
	f := newFixture(t)
	f.store.SetStorageQuota(1000)
	account := handlertest.CreateUser(t, f.store)
	f.authorize(account.UserID, "example-songs")
	f.authorize(account.UserID, "neoworks-photos")

	all := f.usage(account)
	if all.QuotaBytes != 1000 || all.UsedBytes != 0 || len(all.Apps) != 2 {
		t.Fatalf("account view: %+v", all)
	}
	own := f.usage(f.install(account, "example-songs"))
	if own.QuotaBytes != 1000 || len(own.Apps) != 1 || own.Apps[0].ClientID != "example-songs" {
		t.Fatalf("app view: %+v", own)
	}
}

func TestTheUserCapsAnAppAndAppsCannotCapThemselves(t *testing.T) {
	f := newFixture(t)
	account := handlertest.CreateUser(t, f.store)
	f.authorize(account.UserID, "example-songs")
	path := "/api/v1/storage/apps/example-songs/cap"

	if response := f.router.Do(t, account, "PUT", path, map[string]any{"capBytes": 500}, nil); response.Code != http.StatusOK {
		t.Fatalf("set cap: %d %s", response.Code, response.Body.String())
	}
	usage := f.usage(account)
	if usage.Apps[0].CapBytes == nil || *usage.Apps[0].CapBytes != 500 {
		t.Fatalf("cap stored: %+v", usage.Apps)
	}
	app := f.install(account, "example-songs")
	if response := f.router.Do(t, app, "PUT", path, map[string]any{"capBytes": nil}, nil); response.Code != http.StatusForbidden {
		t.Fatalf("an app changing its own cap: %d", response.Code)
	}
	if response := f.router.Do(t, account, "PUT", path, map[string]any{"capBytes": -1}, nil); response.Code != http.StatusBadRequest {
		t.Fatalf("negative cap: %d", response.Code)
	}
	if response := f.router.Do(t, account, "PUT", "/api/v1/storage/apps/never-used/cap", map[string]any{"capBytes": 5}, nil); response.Code != http.StatusNotFound {
		t.Fatalf("cap for an app the user never authorized: %d", response.Code)
	}
	if response := f.router.Do(t, account, "PUT", path, map[string]any{"capBytes": nil}, nil); response.Code != http.StatusOK {
		t.Fatalf("remove cap: %d", response.Code)
	}
	if usage := f.usage(account); usage.Apps[0].CapBytes != nil {
		t.Fatalf("cap removed: %+v", usage.Apps)
	}
}
