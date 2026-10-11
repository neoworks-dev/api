package apps_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/handlers/apps"
	"github.com/neoworks/auth/handlers/handlertest"
	"github.com/neoworks/auth/ownership"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
	"golang.org/x/crypto/bcrypt"
)

type fixture struct {
	t      *testing.T
	store  *database.SurrealStore
	router *handlertest.Router
}

func newFixture(t *testing.T) *fixture {
	return newFixtureWith(t, func(*apps.Handler) {})
}

// newFixtureWith lets the test configure the handler before its routes mount.
func newFixtureWith(t *testing.T, configure func(*apps.Handler)) *fixture {
	store := dbtest.New(t)
	handler := apps.NewHandler(store)
	configure(handler)
	router := handlertest.NewAuthenticated(func(router chi.Router) { handler.RegisterAuthenticated(router) })
	return &fixture{t: t, store: store, router: router}
}

// expect sends a request and fails unless the response has the status and, when
// given, the error code. It returns the decoded JSON object.
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

func (f *fixture) userWithHandle(handle string) access.Principal {
	f.t.Helper()
	user := handlertest.CreateUser(f.t, f.store)
	if err := f.store.ClaimUserHandle(context.Background(), user.UserID, handle); err != nil {
		f.t.Fatalf("claim %s: %v", handle, err)
	}
	return user
}

func (f *fixture) organization(handle string, leader access.Principal) {
	f.t.Helper()
	if _, err := f.store.CreateOrganization(context.Background(), leader.UserID, handle, "Acme"); err != nil {
		f.t.Fatalf("create organization: %v", err)
	}
}

func (f *fixture) member(organization string, grants ...ownership.Grant) access.Principal {
	f.t.Helper()
	member := handlertest.CreateUser(f.t, f.store)
	if err := f.store.AddMember(context.Background(), organization, member.UserID, grants); err != nil {
		f.t.Fatalf("add member: %v", err)
	}
	return member
}

// publishCollection publishes @scope/name with a descriptor so scopes can name it.
func (f *fixture) publishCollection(publisher access.Principal, scope string, name string) {
	f.t.Helper()
	_, err := f.store.PublishRegistryVersion(context.Background(), publisher.UserID, database.RegistryPublishInput{
		Scope: scope, Name: name, Version: "1.0.0", Title: "Recipes", Description: "Recipes",
		Files: []database.RegistryPublishFile{{Path: name + ".schema", Contents: "x"}}, Descriptor: `{"descriptorVersion":1}`,
	})
	if err != nil {
		f.t.Fatalf("publish %s/%s: %v", scope, name, err)
	}
}

func appBody(overrides map[string]any) map[string]any {
	body := map[string]any{
		"name": "Recipes", "description": "Share recipes", "homepage": "https://recipes.example.com",
		"type": "public", "redirectUris": []string{"https://recipes.example.com/callback"},
		"scopes": []map[string]string{{"scope": "openid", "reason": "Sign you in"}},
	}
	for key, value := range overrides {
		body[key] = value
	}
	return body
}

func appOf(response map[string]any) map[string]any {
	return response["app"].(map[string]any)
}

func (f *fixture) createApp(principal access.Principal, owner string, overrides map[string]any) map[string]any {
	f.t.Helper()
	return f.expect(principal, "POST", "/api/v1/owners/"+owner+"/apps", appBody(overrides), http.StatusCreated, "")
}

func permissionsOf(app map[string]any) []string {
	permissions := []string{}
	for _, permission := range app["myPermissions"].([]any) {
		permissions = append(permissions, permission.(string))
	}
	return permissions
}

func TestAPersonCreatesAPublicAppThatIsNeverFirstParty(t *testing.T) {
	f := newFixture(t)
	owner := f.userWithHandle("moritz")

	created := f.createApp(owner, "moritz", map[string]any{"firstParty": true})
	app := appOf(created)
	if _, hasSecret := created["clientSecret"]; hasSecret || app["type"] != "public" || app["reviewStatus"] != "none" || app["verified"] != false {
		t.Fatalf("created: %v", created)
	}
	if appOwner := app["owner"].(map[string]any); appOwner["handle"] != "moritz" || appOwner["kind"] != "user" {
		t.Fatalf("owner: %v", app["owner"])
	}
	if len(permissionsOf(app)) != len(ownership.PerAppPermissions) {
		t.Fatalf("a person acts with every permission: %v", app["myPermissions"])
	}
	client, err := f.store.GetClient(context.Background(), app["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if client.FirstParty || !client.Public || client.SecretHash != "" {
		t.Fatalf("stored client: %+v", client)
	}

	listed := f.expect(owner, "GET", "/api/v1/owners/moritz/apps", nil, http.StatusOK, "")
	if len(listed["apps"].([]any)) != 1 {
		t.Fatalf("listed: %v", listed)
	}
	got := f.expect(owner, "GET", "/api/v1/apps/"+app["id"].(string), nil, http.StatusOK, "")
	if got["name"] != "Recipes" || got["homepage"] != "https://recipes.example.com" || got["logoUrl"] != nil {
		t.Fatalf("got: %v", got)
	}
}

func TestConfidentialAppsGetASecretShownOnceThatOauthVerifies(t *testing.T) {
	f := newFixture(t)
	owner := f.userWithHandle("moritz")

	created := f.createApp(owner, "moritz", map[string]any{"type": "confidential"})
	secret, _ := created["clientSecret"].(string)
	clientID := appOf(created)["id"].(string)
	if secret == "" {
		t.Fatalf("a confidential app gets a secret: %v", created)
	}
	client, err := f.store.GetClient(context.Background(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	if client.Public || bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(secret)) != nil {
		t.Fatalf("the stored hash must verify the secret: %+v", client)
	}
	if again := f.expect(owner, "GET", "/api/v1/apps/"+clientID, nil, http.StatusOK, ""); again["clientSecret"] != nil {
		t.Fatalf("the secret is shown once: %v", again)
	}

	rotated := f.expect(owner, "POST", "/api/v1/apps/"+clientID+"/secret", nil, http.StatusOK, "")["clientSecret"].(string)
	client, _ = f.store.GetClient(context.Background(), clientID)
	if rotated == secret || bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(rotated)) != nil ||
		bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(secret)) == nil {
		t.Fatal("rotating replaces the secret")
	}

	public := appOf(f.createApp(owner, "moritz", nil))["id"].(string)
	refused := f.expect(owner, "POST", "/api/v1/apps/"+public+"/secret", nil, http.StatusBadRequest, "invalid_request")
	if refused["field"] != "type" {
		t.Fatalf("public apps have no secret: %v", refused)
	}
}

func TestOnlyTheOwnerSeesAndEditsAPersonalApp(t *testing.T) {
	f := newFixture(t)
	owner := f.userWithHandle("moritz")
	stranger := f.userWithHandle("stranger")
	clientID := appOf(f.createApp(owner, "moritz", nil))["id"].(string)

	f.expect(stranger, "GET", "/api/v1/owners/moritz/apps", nil, http.StatusNotFound, "not_found")
	f.expect(stranger, "POST", "/api/v1/owners/moritz/apps", appBody(nil), http.StatusNotFound, "not_found")
	f.expect(stranger, "GET", "/api/v1/apps/"+clientID, nil, http.StatusNotFound, "not_found")
	f.expect(stranger, "PATCH", "/api/v1/apps/"+clientID, map[string]any{"name": "Mine"}, http.StatusNotFound, "not_found")
	f.expect(stranger, "DELETE", "/api/v1/apps/"+clientID, nil, http.StatusNotFound, "not_found")
	f.expect(owner, "GET", "/api/v1/owners/nobody/apps", nil, http.StatusNotFound, "not_found")
	f.expect(owner, "GET", "/api/v1/apps/no-such-app", nil, http.StatusNotFound, "not_found")

	updated := f.expect(owner, "PATCH", "/api/v1/apps/"+clientID, map[string]any{"name": "Renamed"}, http.StatusOK, "")
	if updated["name"] != "Renamed" || updated["description"] != "Share recipes" {
		t.Fatalf("patch changes only the given fields: %v", updated)
	}
	f.expect(owner, "PATCH", "/api/v1/apps/"+clientID, map[string]any{"type": "confidential"}, http.StatusBadRequest, "invalid_request")
}

func TestMembersActWithTheirPermissionsAtTheirReach(t *testing.T) {
	f := newFixture(t)
	leader := f.userWithHandle("founder")
	f.organization("acme", leader)
	creator := f.member("acme", ownership.OrganizationWide(ownership.AppsCreate))
	viewer := f.member("acme")
	first := appOf(f.createApp(leader, "acme", nil))["id"].(string)
	second := appOf(f.createApp(leader, "acme", map[string]any{"name": "Second"}))["id"].(string)
	scoped := f.member("acme", ownership.ForApp(ownership.AppsEdit, first))

	f.expect(viewer, "POST", "/api/v1/owners/acme/apps", appBody(nil), http.StatusForbidden, "missing_permission")
	if listed := f.expect(viewer, "GET", "/api/v1/owners/acme/apps", nil, http.StatusOK, ""); len(listed["apps"].([]any)) != 2 {
		t.Fatalf("every member sees the apps: %v", listed)
	}
	denied := f.expect(viewer, "PATCH", "/api/v1/apps/"+first, map[string]any{"name": "X"}, http.StatusForbidden, "missing_permission")
	if denied["permission"] != "apps.edit" {
		t.Fatalf("the refusal names the permission: %v", denied)
	}

	f.expect(scoped, "PATCH", "/api/v1/apps/"+first, map[string]any{"name": "Edited"}, http.StatusOK, "")
	f.expect(scoped, "PATCH", "/api/v1/apps/"+second, map[string]any{"name": "Edited"}, http.StatusForbidden, "missing_permission")
	f.expect(scoped, "DELETE", "/api/v1/apps/"+first, nil, http.StatusForbidden, "missing_permission")
	if view := f.expect(scoped, "GET", "/api/v1/apps/"+first, nil, http.StatusOK, ""); len(permissionsOf(view)) != 1 {
		t.Fatalf("myPermissions lists the permissions on this app: %v", view)
	}

	own := f.createApp(creator, "acme", map[string]any{"type": "confidential"})
	ownPermissions := permissionsOf(appOf(own))
	if len(ownPermissions) != len(ownership.PerAppPermissions) {
		t.Fatalf("the creator gets every per-app permission on the new app: %v", ownPermissions)
	}
	f.expect(creator, "POST", "/api/v1/apps/"+appOf(own)["id"].(string)+"/secret", nil, http.StatusOK, "")
	f.expect(creator, "PATCH", "/api/v1/apps/"+first, map[string]any{"name": "X"}, http.StatusForbidden, "missing_permission")
}

func TestACreatorHoldingThePermissionsOrganizationWideGetsNoPerAppGrants(t *testing.T) {
	f := newFixture(t)
	leader := f.userWithHandle("founder")
	f.organization("acme", leader)
	f.createApp(leader, "acme", nil)

	member, err := f.store.GetMember(context.Background(), "acme", leader.UserID)
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range member.Grants {
		if grant.AppID != nil {
			t.Fatalf("an organization-wide holder needs no per-app grant: %+v", member.Grants)
		}
	}
}

func TestInvalidFieldsAreRefusedWithTheFieldNamed(t *testing.T) {
	f := newFixture(t)
	owner := f.userWithHandle("moritz")
	cases := map[string]struct {
		overrides map[string]any
		field     string
		code      string
	}{
		"no name":          {map[string]any{"name": " "}, "name", "invalid_request"},
		"long name":        {map[string]any{"name": string(make([]byte, 61))}, "name", "invalid_request"},
		"bad type":         {map[string]any{"type": "hybrid"}, "type", "invalid_request"},
		"no type":          {map[string]any{"type": nil}, "type", "invalid_request"},
		"http homepage":    {map[string]any{"homepage": "http://example.com"}, "homepage", "invalid_request"},
		"no redirects":     {map[string]any{"redirectUris": []string{}}, "redirectUris", "invalid_request"},
		"plain http":       {map[string]any{"redirectUris": []string{"http://example.com/cb"}}, "redirectUris", "invalid_request"},
		"loopback no port": {map[string]any{"redirectUris": []string{"http://localhost/cb"}}, "redirectUris", "invalid_request"},
		"port too large":   {map[string]any{"redirectUris": []string{"http://localhost:99999/cb"}}, "redirectUris", "invalid_request"},
		"flat scheme":      {map[string]any{"redirectUris": []string{"myapp://cb"}}, "redirectUris", "invalid_request"},
		"duplicate uris":   {map[string]any{"redirectUris": []string{"https://a.example.com/cb", "https://a.example.com/cb"}}, "redirectUris", "invalid_request"},
		"unknown scope":    {map[string]any{"scopes": []map[string]string{{"scope": "admin", "reason": "x"}}}, "scopes", "invalid_request"},
		"service scope":    {map[string]any{"scopes": []map[string]string{{"scope": "schemas:publish", "reason": "x"}}}, "scopes", "invalid_request"},
		"bad action":       {map[string]any{"scopes": []map[string]string{{"scope": "@acme/recipes:admin", "reason": "x"}}}, "scopes", "invalid_request"},
		"no reason":        {map[string]any{"scopes": []map[string]string{{"scope": "openid", "reason": ""}}}, "scopes", "invalid_request"},
		"duplicate scope":  {map[string]any{"scopes": []map[string]string{{"scope": "openid", "reason": "a"}, {"scope": "openid", "reason": "b"}}}, "scopes", "invalid_request"},
		"unpublished":      {map[string]any{"scopes": []map[string]string{{"scope": "@acme/recipes:read", "reason": "x"}}}, "scopes", "unknown_collection"},
	}
	for name, testCase := range cases {
		response := f.expect(owner, "POST", "/api/v1/owners/moritz/apps", appBody(testCase.overrides), http.StatusBadRequest, testCase.code)
		if response["field"] != testCase.field {
			t.Errorf("%s: got field %v want %s", name, response["field"], testCase.field)
		}
	}
	valid := map[string]any{"redirectUris": []string{
		"https://example.com/cb", "http://localhost:5173/cb", "http://127.0.0.1:8765/callback", "com.example.app://callback",
	}}
	f.createApp(owner, "moritz", valid)
	if listed := f.expect(owner, "GET", "/api/v1/owners/moritz/apps", nil, http.StatusOK, ""); len(listed["apps"].([]any)) != 1 {
		t.Fatalf("refused apps are not stored: %v", listed)
	}
}

func TestScopesOfPublishedCollectionsAreAccepted(t *testing.T) {
	f := newFixture(t)
	owner := f.userWithHandle("acme")
	f.publishCollection(owner, "acme", "recipes")
	scopes := []map[string]string{
		{"scope": "@acme/recipes:read", "reason": "Show recipes"},
		{"scope": "@acme/recipes:write", "reason": "Save recipes"},
		{"scope": "@acme/recipes:share", "reason": "Share recipes"},
	}
	clientID := appOf(f.createApp(owner, "acme", map[string]any{"scopes": scopes}))["id"].(string)

	update := f.expect(owner, "PATCH", "/api/v1/apps/"+clientID,
		map[string]any{"scopes": []map[string]string{{"scope": "@acme/missing:read", "reason": "x"}}}, http.StatusBadRequest, "unknown_collection")
	if update["field"] != "scopes" {
		t.Fatalf("unpublished collection on update: %v", update)
	}
	client, err := f.store.GetClient(context.Background(), clientID)
	if err != nil || len(client.Scopes) != 3 {
		t.Fatalf("the oauth server reads the scopes as plain strings: %+v %v", client, err)
	}
}

func TestDeletingAnAppRevokesItsAccessAndRemovesGrantsNamingIt(t *testing.T) {
	f := newFixture(t)
	leader := f.userWithHandle("founder")
	f.organization("acme", leader)
	clientID := appOf(f.createApp(leader, "acme", nil))["id"].(string)
	remaining := appOf(f.createApp(leader, "acme", map[string]any{"name": "Other"}))["id"].(string)
	member := f.member("acme", ownership.ForApp(ownership.AppsEdit, clientID), ownership.ForApp(ownership.AppsEdit, remaining))
	user := handlertest.CreateUser(t, f.store)
	ctx := context.Background()
	if _, err := f.store.CreateInstall(ctx, database.CreateInstallParams{
		InstallID: "install-1", UserID: user.UserID, ClientID: clientID, EncPub: "e", SignPub: "s", Name: "phone",
	}); err != nil {
		t.Fatal(err)
	}
	createRefreshToken(t, f.store, user.UserID, clientID)

	if err := f.store.ArchiveOrganization(ctx, "acme"); err != database.ErrOwnsApps {
		t.Fatalf("an organization owning apps cannot be archived: %v", err)
	}
	f.expect(leader, "DELETE", "/api/v1/apps/"+clientID, nil, http.StatusNoContent, "")
	f.expect(leader, "GET", "/api/v1/apps/"+clientID, nil, http.StatusNotFound, "not_found")

	install, err := f.store.GetInstall(ctx, "install-1")
	if err != nil || install.RevokedAt == nil {
		t.Fatalf("the install is revoked: %+v %v", install, err)
	}
	if revoked := unrevokedRefreshTokens(t, f.store, clientID); revoked != 0 {
		t.Fatalf("%d refresh tokens survived", revoked)
	}
	stored, err := f.store.GetMember(ctx, "acme", member.UserID)
	if err != nil || len(stored.Grants) != 1 || *stored.Grants[0].AppID != remaining {
		t.Fatalf("grants naming the deleted app are removed: %+v %v", stored, err)
	}
	f.expect(leader, "DELETE", "/api/v1/apps/"+remaining, nil, http.StatusNoContent, "")
	if err := f.store.ArchiveOrganization(ctx, "acme"); err != nil {
		t.Fatalf("an organization without apps can be archived: %v", err)
	}
	f.expect(leader, "POST", "/api/v1/owners/acme/apps", appBody(nil), http.StatusConflict, "archived")
}

func createRefreshToken(t *testing.T, store *database.SurrealStore, userID string, clientID string) {
	t.Helper()
	_, err := surrealdb.Query[any](context.Background(), store.DB,
		"CREATE refresh_token SET user = $user, client = $client, scopes = [], expires_at = time::now() + 1d",
		map[string]any{"user": models.NewRecordID("user", userID), "client": models.NewRecordID("client", clientID)})
	if err != nil {
		t.Fatal(err)
	}
}

func unrevokedRefreshTokens(t *testing.T, store *database.SurrealStore, clientID string) int {
	t.Helper()
	results, err := surrealdb.Query[[]struct {
		Count int `json:"count"`
	}](context.Background(), store.DB,
		"SELECT count() FROM refresh_token WHERE client = $client AND revoked = false GROUP ALL",
		map[string]any{"client": models.NewRecordID("client", clientID)})
	if err != nil {
		t.Fatal(err)
	}
	rows := (*results)[0].Result
	if len(rows) == 0 {
		return 0
	}
	return rows[0].Count
}

func TestOrganizationAppChangesAreAudited(t *testing.T) {
	f := newFixture(t)
	leader := f.userWithHandle("founder")
	f.organization("acme", leader)
	f.publishCollection(leader, "founder", "recipes")
	clientID := appOf(f.createApp(leader, "acme", map[string]any{"type": "confidential"}))["id"].(string)

	f.expect(leader, "PATCH", "/api/v1/apps/"+clientID, map[string]any{"name": "Renamed"}, http.StatusOK, "")
	f.expect(leader, "PATCH", "/api/v1/apps/"+clientID, map[string]any{"redirectUris": []string{"https://other.example.com/cb"}}, http.StatusOK, "")
	f.expect(leader, "PATCH", "/api/v1/apps/"+clientID,
		map[string]any{"scopes": []map[string]string{{"scope": "@founder/recipes:read", "reason": "x"}}}, http.StatusOK, "")
	f.expect(leader, "POST", "/api/v1/apps/"+clientID+"/secret", nil, http.StatusOK, "")
	f.expect(leader, "DELETE", "/api/v1/apps/"+clientID, nil, http.StatusNoContent, "")

	page, err := f.store.ListAudit(context.Background(), "acme", time.Time{}, 50)
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]int{}
	for _, entry := range page.Entries {
		actions[entry.Action]++
		if entry.Target.Kind == "app" && (entry.Target.ID != clientID || entry.Actor.Handle != "founder") {
			t.Errorf("entry %s names the wrong target or actor: %+v", entry.Action, entry)
		}
	}
	for _, action := range []string{
		database.AuditAppCreated, database.AuditAppRedirectURIsChanged, database.AuditAppScopesChanged,
		database.AuditAppSecretRotated, database.AuditAppDeleted,
	} {
		if actions[action] != 1 {
			t.Errorf("audit action %s recorded %d times", action, actions[action])
		}
	}
}

func TestSeedClientsBelongToNeoworksAndTheSampleHasNoOwner(t *testing.T) {
	f := newFixture(t)
	staff := f.member("neoworks", ownership.OrganizationWide(ownership.AppsEdit))

	listed := f.expect(staff, "GET", "/api/v1/owners/neoworks/apps", nil, http.StatusOK, "")
	ids := map[string]bool{}
	for _, app := range listed["apps"].([]any) {
		ids[app.(map[string]any)["id"].(string)] = true
	}
	for _, id := range []string{"neoworks.dev", "neoworks-calendar", "neoworks-contacts", "neoworks-photos", "openschema"} {
		if !ids[id] {
			t.Errorf("%s is not owned by neoworks", id)
		}
	}
	if ids["example-songs"] {
		t.Error("example-songs has no owner")
	}
	f.expect(staff, "GET", "/api/v1/apps/example-songs", nil, http.StatusNotFound, "not_found")
	f.expect(staff, "GET", "/api/v1/apps/neoworks-calendar", nil, http.StatusOK, "")
}

var zeroTime time.Time
