package keys_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/handlers/handlertest"
	"github.com/neoworks/auth/handlers/keys"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
)

func newRouter(t *testing.T) (*handlertest.Router, *database.SurrealStore) {
	store := dbtest.New(t)
	handler := keys.NewHandler(store)
	return handlertest.NewAuthenticated(func(router chi.Router) { handler.RegisterAuthenticated(router) }), store
}

func nextBundle(version int) database.KeyBundle {
	return database.KeyBundle{
		Version: version, AmkPassword: "p2", AmkRecovery: "r2", IdentityPrivate: "i2",
		EncPub: "e2", SignPub: "s2", SelfSig: "sig2",
	}
}

func TestBundleRotationWithMatchingVersion(t *testing.T) {
	router, store := newRouter(t)
	user := handlertest.CreateUser(t, store)

	read := router.Do(t, user, "GET", "/api/v1/keys/bundle", nil, nil)
	if read.Code != http.StatusOK {
		t.Fatalf("get bundle: %d %s", read.Code, read.Body.String())
	}
	rotate := router.Do(t, user, "PUT", "/api/v1/keys/bundle", nextBundle(2), map[string]string{"If-Match": "1"})
	if rotate.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rotate.Code, rotate.Body.String())
	}
	var rotated database.KeyBundle
	handlertest.Decode(t, router.Do(t, user, "GET", "/api/v1/keys/bundle", nil, nil), &rotated)
	if rotated.Version != 2 || rotated.AmkPassword != "p2" {
		t.Fatalf("bundle after rotation: %+v", rotated)
	}
}

func TestBundleRotationWithStaleVersionIs409(t *testing.T) {
	router, store := newRouter(t)
	user := handlertest.CreateUser(t, store)
	router.Do(t, user, "PUT", "/api/v1/keys/bundle", nextBundle(2), map[string]string{"If-Match": "1"})

	stale := router.Do(t, user, "PUT", "/api/v1/keys/bundle", nextBundle(2), map[string]string{"If-Match": "1"})
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale rotation: got %d want 409", stale.Code)
	}
	var body struct {
		Version int `json:"version"`
	}
	handlertest.Decode(t, stale, &body)
	if body.Version != 2 {
		t.Fatalf("409 should report the current version 2, got %d", body.Version)
	}
}

func TestBundleRotationValidatesInput(t *testing.T) {
	router, store := newRouter(t)
	user := handlertest.CreateUser(t, store)

	if response := router.Do(t, user, "PUT", "/api/v1/keys/bundle", nextBundle(2), nil); response.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing If-Match: got %d want 428", response.Code)
	}
	if response := router.Do(t, user, "PUT", "/api/v1/keys/bundle", nextBundle(5), map[string]string{"If-Match": "1"}); response.Code != http.StatusBadRequest {
		t.Fatalf("version jump: got %d want 400", response.Code)
	}
	incomplete := nextBundle(2)
	incomplete.SelfSig = ""
	if response := router.Do(t, user, "PUT", "/api/v1/keys/bundle", incomplete, map[string]string{"If-Match": "1"}); response.Code != http.StatusBadRequest {
		t.Fatalf("incomplete bundle: got %d want 400", response.Code)
	}
}

func TestInstallTokensCannotTouchTheBundle(t *testing.T) {
	router, store := newRouter(t)
	user := handlertest.CreateUser(t, store)
	app := access.Principal{UserID: user.UserID, InstallID: "11111111-1111-4111-8111-111111111111"}

	if response := router.Do(t, app, "GET", "/api/v1/keys/bundle", nil, nil); response.Code != http.StatusForbidden {
		t.Fatalf("install reading bundle: got %d want 403", response.Code)
	}
	if response := router.Do(t, app, "PUT", "/api/v1/keys/bundle", nextBundle(2), map[string]string{"If-Match": "1"}); response.Code != http.StatusForbidden {
		t.Fatalf("install rotating bundle: got %d want 403", response.Code)
	}
}

func TestIdentityLookup(t *testing.T) {
	router, store := newRouter(t)
	user := handlertest.CreateUser(t, store)
	other := handlertest.CreateUser(t, store)
	app := access.Principal{UserID: user.UserID, InstallID: "11111111-1111-4111-8111-111111111111"}

	byID := router.Do(t, app, "GET", "/api/v1/keys/identity?userId="+other.UserID, nil, nil)
	if byID.Code != http.StatusOK {
		t.Fatalf("install lookup by id: got %d", byID.Code)
	}
	if response := router.Do(t, app, "GET", "/api/v1/keys/identity?email=x@example.com", nil, nil); response.Code != http.StatusBadRequest {
		t.Fatalf("install lookup by email: got %d want 400", response.Code)
	}
	if response := router.Do(t, user, "GET", "/api/v1/keys/identity?userId=11111111-1111-4111-8111-111111111111", nil, nil); response.Code != http.StatusNotFound {
		t.Fatalf("unknown user: got %d want 404", response.Code)
	}
}

func TestIdentityKeyHistoryListsVersionsOldestFirst(t *testing.T) {
	router, store := newRouter(t)
	user := handlertest.CreateUser(t, store)
	statement := `
		UPDATE identity_key SET retired_at = time::now() WHERE user = $user AND version = 1;
		CREATE identity_key SET user = $user, version = 2, sign_pub = 'sign2', enc_pub = 'enc2', rotation_sig = 'link';`
	params := map[string]any{"user": models.NewRecordID("user", user.UserID)}
	if _, err := surrealdb.Query[any](context.Background(), store.DB, statement, params); err != nil {
		t.Fatalf("append version: %v", err)
	}

	response := router.Do(t, user, "GET", "/api/v1/users/"+user.UserID+"/identity-keys", nil, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("history: %d %s", response.Code, response.Body.String())
	}
	var body struct {
		Keys []database.IdentityKey `json:"keys"`
	}
	handlertest.Decode(t, response, &body)
	if len(body.Keys) != 2 || body.Keys[0].Version != 1 || body.Keys[1].Version != 2 {
		t.Fatalf("keys: %+v", body.Keys)
	}
	if body.Keys[0].RetiredAt == nil || body.Keys[1].RetiredAt != nil || body.Keys[0].RotationSig != "" || body.Keys[1].RotationSig != "link" {
		t.Fatalf("retirement or links wrong: %+v", body.Keys)
	}
}

func TestIdentityKeyHistoryOfUnknownUserIs404(t *testing.T) {
	router, store := newRouter(t)
	user := handlertest.CreateUser(t, store)
	response := router.Do(t, user, "GET", "/api/v1/users/"+uuid.NewString()+"/identity-keys", nil, nil)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown user: got %d want 404", response.Code)
	}
}
