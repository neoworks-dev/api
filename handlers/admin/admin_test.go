package admin_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/handlers/admin"
	"github.com/neoworks/auth/handlers/handlertest"
	"github.com/neoworks/auth/ownership"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
)

type fixture struct {
	t      *testing.T
	store  *database.SurrealStore
	router *handlertest.Router
}

func newFixture(t *testing.T) *fixture {
	store := dbtest.New(t)
	handler := admin.NewHandler(store)
	router := handlertest.NewAuthenticated(func(router chi.Router) { handler.RegisterAuthenticated(router) })
	return &fixture{t: t, store: store, router: router}
}

func (f *fixture) expect(principal access.Principal, method, path string, body any, status int, errorCode string) map[string]any {
	f.t.Helper()
	response := f.router.Do(f.t, principal, method, path, body, nil)
	if response.Code != status {
		f.t.Fatalf("%s %s: got %d want %d: %s", method, path, response.Code, status, response.Body.String())
	}
	decoded := map[string]any{}
	if response.Body.Len() > 0 {
		handlertest.Decode(f.t, response, &decoded)
	}
	if errorCode != "" && decoded["error"] != errorCode {
		f.t.Fatalf("%s %s: got error %v want %s", method, path, decoded["error"], errorCode)
	}
	return decoded
}

// administrator is a member of the neoworks organization with platform.admin.
func (f *fixture) administrator() access.Principal {
	f.t.Helper()
	user := handlertest.CreateUser(f.t, f.store)
	grants := []ownership.Grant{ownership.OrganizationWide(ownership.PlatformAdmin)}
	if err := f.store.AddMember(context.Background(), ownership.PlatformOrganization, user.UserID, grants); err != nil {
		f.t.Fatal(err)
	}
	return user
}

// developerWithApp registers a person's app that asked for review.
func (f *fixture) developerWithApp(handle string) (access.Principal, string) {
	f.t.Helper()
	user := handlertest.CreateUser(f.t, f.store)
	if err := f.store.ClaimUserHandle(context.Background(), user.UserID, handle); err != nil {
		f.t.Fatal(err)
	}
	app, err := f.store.CreateApp(context.Background(), database.NewApp{
		ID: "app_" + handle, OwnerHandle: handle, CreatorID: user.UserID, Type: database.AppTypePublic,
		Fields: database.AppFields{Name: "Recipes", Description: "d", Homepage: "https://example.com",
			RedirectURIs: []string{"https://example.com/cb"}, Scopes: []database.RequestedScope{{Scope: "openid", Reason: "r"}}},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	_, err = f.store.SubmitReview(context.Background(), app.ID, database.ReviewSubmission{PrivacyPolicyURL: "https://example.com/p", SupportContact: "a@example.com"})
	if err != nil {
		f.t.Fatal(err)
	}
	return user, app.ID
}

func TestOnlyPlatformAdministratorsUseTheAdminRoutes(t *testing.T) {
	f := newFixture(t)
	developer, clientID := f.developerWithApp("moritz")
	outsider := handlertest.CreateUser(t, f.store)
	otherOrganizationMember := handlertest.CreateUser(t, f.store)
	if err := f.store.ClaimUserHandle(context.Background(), otherOrganizationMember.UserID, "other"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateOrganization(context.Background(), otherOrganizationMember.UserID, "acme", "Acme"); err != nil {
		t.Fatal(err)
	}

	for _, caller := range []access.Principal{developer, outsider, otherOrganizationMember} {
		response := f.expect(caller, "GET", "/api/v1/admin/reviews", nil, http.StatusForbidden, "missing_permission")
		if response["permission"] != "platform.admin" {
			t.Fatalf("permission named: %v", response)
		}
		f.expect(caller, "POST", "/api/v1/admin/apps/"+clientID+"/review", map[string]any{"decision": "approve"}, http.StatusForbidden, "missing_permission")
		f.expect(caller, "PUT", "/api/v1/admin/organizations/acme/verified", map[string]any{"verified": true}, http.StatusForbidden, "missing_permission")
		if session := f.expect(caller, "GET", "/api/v1/admin/session", nil, http.StatusOK, ""); session["admin"] != false {
			t.Fatalf("session of a non-admin: %v", session)
		}
	}
	if session := f.expect(f.administrator(), "GET", "/api/v1/admin/session", nil, http.StatusOK, ""); session["admin"] != true {
		t.Fatalf("session of an admin: %v", session)
	}
}

func TestAnAdministratorApprovesRejectsAndSuspends(t *testing.T) {
	f := newFixture(t)
	_, clientID := f.developerWithApp("moritz")
	reviewer := f.administrator()

	queue := f.expect(reviewer, "GET", "/api/v1/admin/reviews", nil, http.StatusOK, "")["items"].([]any)
	if len(queue) != 1 {
		t.Fatalf("queue: %v", queue)
	}
	item := queue[0].(map[string]any)
	if item["privacyPolicyUrl"] != "https://example.com/p" || item["supportContact"] != "a@example.com" || len(item["scopes"].([]any)) != 1 {
		t.Fatalf("what the reviewer judges by: %v", item)
	}

	f.expect(reviewer, "GET", "/api/v1/admin/reviews?status=none", nil, http.StatusBadRequest, "invalid_request")
	path := "/api/v1/admin/apps/" + clientID + "/review"
	f.expect(reviewer, "POST", path, map[string]any{"decision": "reject"}, http.StatusBadRequest, "invalid_request")
	f.expect(reviewer, "POST", path, map[string]any{"decision": "maybe"}, http.StatusBadRequest, "invalid_request")
	rejected := f.expect(reviewer, "POST", path, map[string]any{"decision": "reject", "reason": "No privacy policy."}, http.StatusOK, "")
	if rejected["app"].(map[string]any)["review"].(map[string]any)["reason"] != "No privacy policy." {
		t.Fatalf("rejected: %v", rejected)
	}
	f.expect(reviewer, "POST", path, map[string]any{"decision": "approve"}, http.StatusConflict, "review_state")

	if _, err := f.store.SubmitReview(context.Background(), clientID, database.ReviewSubmission{PrivacyPolicyURL: "https://example.com/p", SupportContact: "a@example.com"}); err != nil {
		t.Fatal(err)
	}
	f.expect(reviewer, "POST", path, map[string]any{"decision": "approve"}, http.StatusOK, "")
	f.expect(reviewer, "POST", path, map[string]any{"decision": "suspend", "reason": "Abuse reports."}, http.StatusOK, "")
	standing, err := f.store.GetClientStanding(context.Background(), clientID)
	if err != nil || !standing.Suspended() {
		t.Fatalf("standing after suspension: %+v %v", standing, err)
	}
	f.expect(reviewer, "POST", path, map[string]any{"decision": "approve"}, http.StatusOK, "")
	if standing, _ := f.store.GetClientStanding(context.Background(), clientID); standing.Suspended() {
		t.Fatal("approving lifts the suspension")
	}
}

func TestDecisionsOnOrganizationAppsAreAuditedWithTheAdministratorAsActor(t *testing.T) {
	f := newFixture(t)
	leader := handlertest.CreateUser(t, f.store)
	if err := f.store.ClaimUserHandle(context.Background(), leader.UserID, "founder"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateOrganization(context.Background(), leader.UserID, "acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	app, err := f.store.CreateApp(context.Background(), database.NewApp{
		ID: "app_acme", OwnerHandle: "acme", CreatorID: leader.UserID, Type: database.AppTypePublic,
		Fields: database.AppFields{Name: "Acme", RedirectURIs: []string{"https://acme.example/cb"}, Scopes: []database.RequestedScope{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	reviewer := f.administrator()
	f.expect(reviewer, "POST", "/api/v1/admin/apps/"+app.ID+"/review", map[string]any{"decision": "suspend", "reason": "Spam."}, http.StatusOK, "")
	f.expect(reviewer, "PUT", "/api/v1/admin/organizations/acme/verified", map[string]any{"verified": true}, http.StatusOK, "")

	page, err := f.store.ListAudit(context.Background(), "acme", zero, 10)
	if err != nil {
		t.Fatal(err)
	}
	if page.Entries[0].Action != database.AuditOrganizationVerifiedChanged || page.Entries[1].Action != database.AuditAppSuspended {
		t.Fatalf("audit: %+v", page.Entries)
	}
	owner, _ := f.store.GetOwner(context.Background(), "acme")
	if !owner.Verified {
		t.Fatal("the organization is verified")
	}
	f.expect(reviewer, "PUT", "/api/v1/admin/organizations/acme/verified", map[string]any{"verified": false}, http.StatusOK, "")
	if owner, _ := f.store.GetOwner(context.Background(), "acme"); owner.Verified {
		t.Fatal("verification can be withdrawn")
	}
	f.expect(reviewer, "PUT", "/api/v1/admin/organizations/founder/verified", map[string]any{"verified": true}, http.StatusNotFound, "not_found")
}

func TestAdministratorsTuneTheRateLimitOfAClient(t *testing.T) {
	f := newFixture(t)
	_, clientID := f.developerWithApp("moritz")
	reviewer := f.administrator()
	path := "/api/v1/admin/apps/" + clientID + "/rate-limit"
	f.expect(reviewer, "PUT", path, map[string]any{"multiplier": 2.5}, http.StatusOK, "")
	standing, err := f.store.GetClientStanding(context.Background(), clientID)
	if err != nil || standing.Multiplier == nil || *standing.Multiplier != 2.5 {
		t.Fatalf("standing: %+v %v", standing, err)
	}
	f.expect(reviewer, "PUT", path, map[string]any{"multiplier": 0}, http.StatusBadRequest, "invalid_request")
	f.expect(reviewer, "PUT", path, map[string]any{"multiplier": 1000}, http.StatusBadRequest, "invalid_request")
	f.expect(reviewer, "PUT", path, map[string]any{"multiplier": nil}, http.StatusOK, "")
	if standing, _ := f.store.GetClientStanding(context.Background(), clientID); standing.Multiplier != nil {
		t.Fatal("null returns the client to its derived multiplier")
	}
	f.expect(reviewer, "PUT", "/api/v1/admin/apps/nope/rate-limit", map[string]any{"multiplier": 2}, http.StatusNotFound, "not_found")
}

func TestBootstrapMakesNamedAccountsAdministrators(t *testing.T) {
	f := newFixture(t)
	user := handlertest.CreateUser(t, f.store)
	loaded, err := f.store.GetUserByID(context.Background(), user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.EnsurePlatformAdmins(context.Background(), []string{"", " " + loaded.Email + " ", "nobody@example.com"}); err != nil {
		t.Fatal(err)
	}
	if admin, err := f.store.IsPlatformAdmin(context.Background(), user.UserID); err != nil || !admin {
		t.Fatalf("bootstrapped admin: %v %v", admin, err)
	}
	if err := f.store.EnsurePlatformAdmins(context.Background(), []string{loaded.Email}); err != nil {
		t.Fatalf("running the bootstrap twice: %v", err)
	}
}

var zero time.Time
