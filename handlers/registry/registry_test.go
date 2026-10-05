package registry_test

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/handlertest"
	"github.com/neoworks/auth/handlers/registry"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
)

type fixture struct {
	router *handlertest.Router
	store  *database.SurrealStore
}

func newFixture(t *testing.T) fixture {
	store := dbtest.New(t)
	handler := registry.NewHandler(store)
	router := handlertest.NewAuthenticated(func(router chi.Router) {
		handler.RegisterPublic(router)
		handler.RegisterAuthenticated(router)
	})
	return fixture{router: router, store: store}
}

func publishBody(version string) map[string]any {
	return map[string]any{
		"version": version, "description": "Orders and customers", "license": "MIT",
		"repository": "https://example.com/commerce", "readme": "# Commerce", "targets": []string{"sql", "go"},
		"files": []map[string]string{
			{"path": "orders.schema", "contents": "namespace commerce"},
			{"path": "customers.schema", "contents": "table customers"},
		},
	}
}

const commercePath = "/api/v1/schemas/acme/commerce"

func TestPublishCreatesSchemaOwnedByThePublisherAndIsPubliclyReadable(t *testing.T) {
	f := newFixture(t)
	owner := handlertest.CreateUser(t, f.store, registry.PublishScope)

	published := f.router.Do(t, owner, "POST", commercePath+"/versions", publishBody("1.0.0"), nil)
	if published.Code != http.StatusCreated {
		t.Fatalf("publish: %d %s", published.Code, published.Body.String())
	}

	var detail struct {
		Schema   database.RegistrySchema    `json:"schema"`
		Versions []database.RegistryVersion `json:"versions"`
	}
	handlertest.Decode(t, f.router.DoAnonymous(t, "GET", commercePath), &detail)
	if detail.Schema.OwnerID != owner.UserID || detail.Schema.LatestVersion != "1.0.0" || detail.Schema.Description != "Orders and customers" {
		t.Fatalf("schema: %+v", detail.Schema)
	}
	if len(detail.Versions) != 1 || detail.Versions[0].Version != "1.0.0" {
		t.Fatalf("versions: %+v", detail.Versions)
	}

	var version database.RegistryVersion
	handlertest.Decode(t, f.router.DoAnonymous(t, "GET", commercePath+"/versions/1.0.0"), &version)
	if version.Readme != "# Commerce" || len(version.Files) != 2 || version.Files[0].Path != "orders.schema" || version.Files[1].Ordinal != 1 {
		t.Fatalf("version: %+v", version)
	}
}

func TestPublishNeedsThePublishScope(t *testing.T) {
	f := newFixture(t)
	withoutScope := handlertest.CreateUser(t, f.store, "openid")
	if response := f.router.Do(t, withoutScope, "POST", commercePath+"/versions", publishBody("1.0.0"), nil); response.Code != http.StatusForbidden {
		t.Fatalf("publish without scope: got %d want 403", response.Code)
	}
	if missing := f.router.DoAnonymous(t, "GET", commercePath); missing.Code != http.StatusNotFound {
		t.Fatalf("nothing was created: got %d want 404", missing.Code)
	}
}

func TestVersionsAreImmutableAndLatestFollowsTheLastPublish(t *testing.T) {
	f := newFixture(t)
	owner := handlertest.CreateUser(t, f.store, registry.PublishScope)
	f.router.Do(t, owner, "POST", commercePath+"/versions", publishBody("1.0.0"), nil)

	changed := publishBody("1.0.0")
	changed["readme"] = "overwritten"
	if again := f.router.Do(t, owner, "POST", commercePath+"/versions", changed, nil); again.Code != http.StatusConflict {
		t.Fatalf("republish: got %d want 409: %s", again.Code, again.Body.String())
	}
	if next := f.router.Do(t, owner, "POST", commercePath+"/versions", publishBody("1.1.0"), nil); next.Code != http.StatusCreated {
		t.Fatalf("second version: %d %s", next.Code, next.Body.String())
	}

	var original database.RegistryVersion
	handlertest.Decode(t, f.router.DoAnonymous(t, "GET", commercePath+"/versions/1.0.0"), &original)
	if original.Readme != "# Commerce" {
		t.Fatalf("published version changed: %+v", original)
	}
	var detail struct {
		Schema   database.RegistrySchema    `json:"schema"`
		Versions []database.RegistryVersion `json:"versions"`
	}
	handlertest.Decode(t, f.router.DoAnonymous(t, "GET", commercePath), &detail)
	if detail.Schema.LatestVersion != "1.1.0" || len(detail.Versions) != 2 || detail.Versions[0].Version != "1.1.0" {
		t.Fatalf("after second publish: %+v %+v", detail.Schema, detail.Versions)
	}
}

func TestAnotherUserCannotPublishOverASchema(t *testing.T) {
	f := newFixture(t)
	owner := handlertest.CreateUser(t, f.store, registry.PublishScope)
	intruder := handlertest.CreateUser(t, f.store, registry.PublishScope)
	f.router.Do(t, owner, "POST", commercePath+"/versions", publishBody("1.0.0"), nil)

	for _, version := range []string{"1.0.0", "2.0.0"} {
		if response := f.router.Do(t, intruder, "POST", commercePath+"/versions", publishBody(version), nil); response.Code != http.StatusForbidden {
			t.Fatalf("intruder publishing %s: got %d want 403", version, response.Code)
		}
	}
	var detail struct {
		Schema   database.RegistrySchema    `json:"schema"`
		Versions []database.RegistryVersion `json:"versions"`
	}
	handlertest.Decode(t, f.router.DoAnonymous(t, "GET", commercePath), &detail)
	if detail.Schema.LatestVersion != "1.0.0" || len(detail.Versions) != 1 {
		t.Fatalf("intruder changed the schema: %+v", detail)
	}
}

func TestPublishRejectsInvalidInput(t *testing.T) {
	f := newFixture(t)
	owner := handlertest.CreateUser(t, f.store, registry.PublishScope)
	noFiles := publishBody("1.0.0")
	noFiles["files"] = []map[string]string{}
	badVersion := publishBody("not a version")
	escapingPath := publishBody("1.0.0")
	escapingPath["files"] = []map[string]string{{"path": "../x.schema", "contents": "x"}}
	for name, body := range map[string]map[string]any{"no files": noFiles, "bad version": badVersion, "escaping path": escapingPath} {
		if response := f.router.Do(t, owner, "POST", commercePath+"/versions", body, nil); response.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d want 400", name, response.Code)
		}
	}
	if response := f.router.Do(t, owner, "POST", "/api/v1/schemas/Bad%20Scope/x/versions", publishBody("1.0.0"), nil); response.Code != http.StatusBadRequest {
		t.Errorf("bad scope: got %d want 400", response.Code)
	}
}

func TestListAndSearchArePublic(t *testing.T) {
	f := newFixture(t)
	owner := handlertest.CreateUser(t, f.store, registry.PublishScope)
	identity := publishBody("1.0.0")
	identity["description"] = "Accounts, sessions and roles"
	f.router.Do(t, owner, "POST", "/api/v1/schemas/acme/identity/versions", identity, nil)
	f.router.Do(t, owner, "POST", commercePath+"/versions", publishBody("1.0.0"), nil)

	var all struct {
		Schemas []database.RegistrySchema `json:"schemas"`
	}
	handlertest.Decode(t, f.router.DoAnonymous(t, "GET", "/api/v1/schemas"), &all)
	if len(all.Schemas) != 2 || all.Schemas[0].Name != "commerce" {
		t.Fatalf("list should be newest first: %+v", all.Schemas)
	}

	var byName, byDescription struct {
		Schemas []database.RegistrySchema `json:"schemas"`
	}
	handlertest.Decode(t, f.router.DoAnonymous(t, "GET", "/api/v1/schemas?q=identity"), &byName)
	handlertest.Decode(t, f.router.DoAnonymous(t, "GET", "/api/v1/schemas?q=namespace"), &byDescription)
	if len(byName.Schemas) != 1 || byName.Schemas[0].Name != "identity" {
		t.Fatalf("search by name: %+v", byName.Schemas)
	}
	if len(byDescription.Schemas) != 0 {
		t.Fatalf("file contents are not searched: %+v", byDescription.Schemas)
	}
	var byWord struct {
		Schemas []database.RegistrySchema `json:"schemas"`
	}
	handlertest.Decode(t, f.router.DoAnonymous(t, "GET", "/api/v1/schemas?q=sessions"), &byWord)
	if len(byWord.Schemas) != 1 || byWord.Schemas[0].Name != "identity" {
		t.Fatalf("search by description: %+v", byWord.Schemas)
	}
}
