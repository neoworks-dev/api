package installs_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/handlers/handlertest"
	"github.com/neoworks/auth/handlers/installs"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

func TestInstallLifecycle(t *testing.T) {
	store := dbtest.New(t)
	ctx := context.Background()
	installHandler := installs.NewHandler(store)
	router := handlertest.NewAuthenticated(func(router chi.Router) { installHandler.RegisterAuthenticated(router) })
	user := handlertest.CreateUser(t, store, "@neoworks/calendar:read", "@neoworks/calendar:write")

	installID, certID := uuid.NewString(), uuid.NewString()
	if _, err := store.CreateInstall(ctx, database.CreateInstallParams{
		InstallID: installID, UserID: user.UserID, ClientID: "neoworks-calendar", EncPub: "e", SignPub: "s", Name: "Phone",
	}); err != nil {
		t.Fatalf("create install: %v", err)
	}
	if _, err := store.CreateCertificate(ctx, database.CreateCertificateParams{
		CertID: certID, UserID: user.UserID, InstallID: installID, Bytes: "certbytes", Signature: "certsig",
	}); err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	app := access.Principal{UserID: user.UserID, InstallID: installID, Scopes: user.Scopes}

	var me database.InstallGrant
	response := router.Do(t, app, "GET", "/api/v1/installs/me", nil, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("installs/me: %d %s", response.Code, response.Body.String())
	}
	handlertest.Decode(t, response, &me)
	if me.InstallID != installID || me.Certificate != "certbytes" || me.CertificateSignature != "certsig" || me.Grants == nil {
		t.Fatalf("installs/me payload: %+v", me)
	}
	if forbidden := router.Do(t, user, "GET", "/api/v1/installs/me", nil, nil); forbidden.Code != http.StatusForbidden {
		t.Fatalf("account token on installs/me: got %d want 403", forbidden.Code)
	}
	if forbidden := router.Do(t, app, "GET", "/api/v1/installs", nil, nil); forbidden.Code != http.StatusForbidden {
		t.Fatalf("install token listing installs: got %d want 403", forbidden.Code)
	}

	var list struct {
		Installs []database.Install `json:"installs"`
	}
	handlertest.Decode(t, router.Do(t, user, "GET", "/api/v1/installs", nil, nil), &list)
	if len(list.Installs) != 1 || list.Installs[0].ID != installID {
		t.Fatalf("list: %+v", list)
	}
	if response := router.Do(t, user, "DELETE", "/api/v1/installs/"+installID, nil, nil); response.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", response.Code)
	}
	if response := router.Do(t, user, "DELETE", "/api/v1/installs/"+uuid.NewString(), nil, nil); response.Code != http.StatusNotFound {
		t.Fatalf("revoke unknown: got %d want 404", response.Code)
	}
}

func TestExpiringWithinValidatesTheWindow(t *testing.T) {
	store := dbtest.New(t)
	installHandler := installs.NewHandler(store)
	router := handlertest.NewAuthenticated(func(router chi.Router) { installHandler.RegisterAuthenticated(router) })
	user := handlertest.CreateUser(t, store, "@neoworks/calendar:read")

	for _, window := range []string{"0", "-1", "abc", "400"} {
		if response := router.Do(t, user, "GET", "/api/v1/installs?expiringWithin="+window, nil, nil); response.Code != http.StatusBadRequest {
			t.Errorf("expiringWithin=%s: got %d want 400", window, response.Code)
		}
	}
	var list struct {
		Installs []database.ExpiringInstall `json:"installs"`
	}
	response := router.Do(t, user, "GET", "/api/v1/installs?expiringWithin=7", nil, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("expiringWithin=7: %d", response.Code)
	}
	handlertest.Decode(t, response, &list)
	if list.Installs == nil || len(list.Installs) != 0 {
		t.Fatalf("expected an empty list, got %+v", list)
	}
}

func authorizeClient(t *testing.T, store *database.SurrealStore, userID string, clientID string) {
	t.Helper()
	_, err := surrealdb.Query[[]any](context.Background(), store.DB,
		"UPSERT grant SET user = $user, client = $client, scopes = ['openid'], enabled = true WHERE user = $user AND client = $client",
		map[string]any{"user": models.NewRecordID("user", userID), "client": models.NewRecordID("client", clientID)})
	if err != nil {
		t.Fatal(err)
	}
}

func TestConnectedAppsShowWhoIsBehindEachAppAndWhereItStands(t *testing.T) {
	store := dbtest.New(t)
	ctx := context.Background()
	installHandler := installs.NewHandler(store)
	router := handlertest.NewAuthenticated(func(router chi.Router) { installHandler.RegisterAuthenticated(router) })
	user := handlertest.CreateUser(t, store)
	developer := handlertest.CreateUser(t, store)
	if err := store.ClaimUserHandle(ctx, developer.UserID, "moritz"); err != nil {
		t.Fatal(err)
	}
	app, err := store.CreateApp(ctx, database.NewApp{
		ID: "app_recipes", OwnerHandle: "moritz", CreatorID: developer.UserID, Type: database.AppTypePublic,
		Fields: database.AppFields{Name: "Recipes", Description: "Share recipes", RedirectURIs: []string{"https://recipes.example/cb"}, Scopes: []database.RequestedScope{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	authorizeClient(t, store, user.UserID, app.ID)
	authorizeClient(t, store, user.UserID, "neoworks-calendar")
	authorizeClient(t, store, user.UserID, "example-songs")
	if _, err := store.CreateInstall(ctx, database.CreateInstallParams{InstallID: uuid.NewString(), UserID: user.UserID, ClientID: app.ID, EncPub: "e", SignPub: "s", Name: "Laptop"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DecideReview(ctx, app.ID, database.DecisionSuspend, "Abuse reports."); err != nil {
		t.Fatal(err)
	}

	var list struct {
		Apps []map[string]any `json:"apps"`
	}
	handlertest.Decode(t, router.Do(t, user, "GET", "/api/v1/connected-apps", nil, nil), &list)
	byID := map[string]map[string]any{}
	for _, connected := range list.Apps {
		byID[connected["clientId"].(string)] = connected
	}
	recipes := byID[app.ID]
	owner := recipes["owner"].(map[string]any)
	if recipes["name"] != "Recipes" || owner["handle"] != "moritz" || recipes["verified"] != false || recipes["firstParty"] != false {
		t.Fatalf("third-party app: %v", recipes)
	}
	if recipes["reviewStatus"] != "suspended" || recipes["reviewReason"] != "Abuse reports." || len(recipes["installs"].([]any)) != 1 {
		t.Fatalf("suspension and installs: %v", recipes)
	}
	if storage := recipes["storage"].(map[string]any); storage["usedBytes"] != float64(0) || storage["capBytes"] != nil {
		t.Fatalf("storage: %v", storage)
	}
	if official := byID["neoworks-calendar"]; official["firstParty"] != true || official["verified"] != true || official["owner"].(map[string]any)["handle"] != "neoworks" {
		t.Fatalf("first-party app: %v", official)
	}
	if sample := byID["example-songs"]; sample["owner"] != nil || sample["verified"] != false {
		t.Fatalf("an app without an owner shows none: %v", sample)
	}
	appToken := access.Principal{UserID: user.UserID, InstallID: uuid.NewString(), Scopes: user.Scopes}
	if response := router.Do(t, appToken, "GET", "/api/v1/connected-apps", nil, nil); response.Code != http.StatusForbidden {
		t.Fatalf("an app listing connected apps: %d", response.Code)
	}
}
