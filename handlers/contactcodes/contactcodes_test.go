package contactcodes_test

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/handlers/contactcodes"
	"github.com/neoworks/auth/handlers/handlertest"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
	"github.com/neoworks/auth/utils"
)

const installID = "11111111-1111-4111-8111-111111111111"

func newRouter(t *testing.T) (*handlertest.Router, *database.SurrealStore) {
	store := dbtest.New(t)
	handler := contactcodes.NewHandler(store)
	return handlertest.NewAuthenticated(func(router chi.Router) { handler.RegisterAuthenticated(router) }), store
}

func codeOf(t *testing.T, router *handlertest.Router, principal access.Principal) string {
	t.Helper()
	response := router.Do(t, principal, "GET", "/api/v1/contact-code", nil, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("get code: %d %s", response.Code, response.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	handlertest.Decode(t, response, &body)
	return body.Code
}

func TestCodeIsStableAndResolvesToPublicIdentity(t *testing.T) {
	router, store := newRouter(t)
	owner := handlertest.CreateUser(t, store)
	other := handlertest.CreateUser(t, store)

	code := codeOf(t, router, owner)
	if len(code) != 12 || codeOf(t, router, owner) != code {
		t.Fatalf("code should be 12 characters and stable, got %q", code)
	}

	formatted := code[:4] + "-" + code[4:8] + "-" + code[8:]
	response := router.Do(t, other, "GET", "/api/v1/contact-codes/"+formatted, nil, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("resolve: %d %s", response.Code, response.Body.String())
	}
	var identity database.PublicIdentity
	handlertest.Decode(t, response, &identity)
	if identity.UserID != owner.UserID || identity.EncPub != "enc" || identity.SignPub != "sign" {
		t.Fatalf("resolved identity: %+v", identity)
	}
}

func TestInstallsResolveCodes(t *testing.T) {
	router, store := newRouter(t)
	owner := handlertest.CreateUser(t, store)
	app := access.Principal{UserID: handlertest.CreateUser(t, store).UserID, InstallID: installID}

	response := router.Do(t, app, "GET", "/api/v1/contact-codes/"+codeOf(t, router, owner), nil, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("install resolve: %d", response.Code)
	}
}

func TestRegenerateReplacesTheCodeForAccountsOnly(t *testing.T) {
	router, store := newRouter(t)
	owner := handlertest.CreateUser(t, store)
	app := access.Principal{UserID: owner.UserID, InstallID: installID}
	oldCode := codeOf(t, router, owner)

	if response := router.Do(t, app, "POST", "/api/v1/contact-code/regenerate", nil, nil); response.Code != http.StatusForbidden {
		t.Fatalf("install regenerate: got %d want 403", response.Code)
	}
	if response := router.Do(t, owner, "POST", "/api/v1/contact-code/regenerate", nil, nil); response.Code != http.StatusOK {
		t.Fatalf("regenerate: %d", response.Code)
	}
	if newCode := codeOf(t, router, owner); newCode == oldCode {
		t.Fatal("code did not change")
	}
	if response := router.Do(t, owner, "GET", "/api/v1/contact-codes/"+oldCode, nil, nil); response.Code != http.StatusNotFound {
		t.Fatalf("old code: got %d want 404", response.Code)
	}
}

func TestMalformedAndUnknownCodes(t *testing.T) {
	router, store := newRouter(t)
	caller := handlertest.CreateUser(t, store)

	if response := router.Do(t, caller, "GET", "/api/v1/contact-codes/not-a-code", nil, nil); response.Code != http.StatusBadRequest {
		t.Fatalf("malformed: got %d want 400", response.Code)
	}
	unowned, err := utils.GenerateContactCode()
	if err != nil {
		t.Fatal(err)
	}
	if response := router.Do(t, caller, "GET", "/api/v1/contact-codes/"+unowned, nil, nil); response.Code != http.StatusNotFound {
		t.Fatalf("unowned: got %d want 404", response.Code)
	}
}

func TestFailedLookupsAreRateLimited(t *testing.T) {
	router, store := newRouter(t)
	caller := handlertest.CreateUser(t, store)

	var last int
	for attempt := 0; attempt < 12; attempt++ {
		last = router.Do(t, caller, "GET", "/api/v1/contact-codes/nonsense", nil, nil).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("after repeated failures: got %d want 429", last)
	}
	response := router.Do(t, caller, "GET", "/api/v1/contact-codes/nonsense", nil, nil)
	if response.Header().Get("Retry-After") == "" {
		t.Fatal("429 should carry Retry-After")
	}
}

func TestSuccessfulLookupsAreRateLimitedPerUser(t *testing.T) {
	router, store := newRouter(t)
	caller := handlertest.CreateUser(t, store)
	code := codeOf(t, router, handlertest.CreateUser(t, store))

	var last int
	for attempt := 0; attempt < 31; attempt++ {
		last = router.Do(t, caller, "GET", "/api/v1/contact-codes/"+code, nil, nil).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("31st lookup in a minute: got %d want 429", last)
	}
}
