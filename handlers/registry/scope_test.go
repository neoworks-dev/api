package registry_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/handlers/handlertest"
	"github.com/neoworks/auth/ownership"
)

type problem struct {
	Error      string `json:"error"`
	Permission string `json:"permission"`
}

func (f fixture) expectProblem(principal access.Principal, method string, path string, body any, status int, code string) problem {
	f.t.Helper()
	response := f.router.Do(f.t, principal, method, path, body, nil)
	if response.Code != status {
		f.t.Fatalf("%s %s: got %d want %d: %s", method, path, response.Code, status, response.Body.String())
	}
	var decoded problem
	handlertest.Decode(f.t, response, &decoded)
	if decoded.Error != code {
		f.t.Fatalf("%s %s: got error %q want %q", method, path, decoded.Error, code)
	}
	return decoded
}

// organizationWith creates an organization led by a user with a handle and adds
// members holding the grants.
func (f fixture) organizationWith(handle string, leaderHandle string) access.Principal {
	f.t.Helper()
	leader := f.publisher(f.t, leaderHandle)
	if _, err := f.store.CreateOrganization(context.Background(), leader.UserID, handle, "Acme"); err != nil {
		f.t.Fatalf("create organization: %v", err)
	}
	return leader
}

func (f fixture) addMember(organization string, grants ...ownership.Grant) access.Principal {
	f.t.Helper()
	member := handlertest.CreateUser(f.t, f.store, "schemas:publish")
	if err := f.store.AddMember(context.Background(), organization, member.UserID, grants); err != nil {
		f.t.Fatalf("add member: %v", err)
	}
	return member
}

func TestPublishingIntoAnUnknownHandleIsNotFound(t *testing.T) {
	f := newFixture(t)
	user := f.publisher(t, "someone")
	f.expectProblem(user, "POST", "/api/v1/schemas/nobody/commerce/versions", publishBody("1.0.0"), http.StatusNotFound, "not_found")
}

func TestPublishingIntoAForeignPersonalHandleIsRefusedWithThePermission(t *testing.T) {
	f := newFixture(t)
	f.publisher(t, "moritz")
	stranger := f.publisher(t, "stranger")
	refused := f.expectProblem(stranger, "POST", "/api/v1/schemas/moritz/commerce/versions", publishBody("1.0.0"), http.StatusForbidden, "missing_permission")
	if refused.Permission != string(ownership.SchemasPublish) {
		t.Fatalf("the refusal must name schemas.publish: %+v", refused)
	}
	if missing := f.router.DoAnonymous(t, "GET", "/api/v1/schemas/moritz/commerce"); missing.Code != http.StatusNotFound {
		t.Fatalf("a refused publish creates nothing: %d", missing.Code)
	}
}

func TestOnlyNeoworksMembersPublishIntoTheNeoworksScope(t *testing.T) {
	f := newFixture(t)
	user := f.publisher(t, "someone")
	refused := f.expectProblem(user, "POST", "/api/v1/schemas/neoworks/calendar/versions", publishBody("9.0.0"), http.StatusForbidden, "missing_permission")
	if refused.Permission != string(ownership.SchemasPublish) {
		t.Fatalf("the refusal must name schemas.publish: %+v", refused)
	}
	staff := f.addMember("neoworks", ownership.OrganizationWide(ownership.SchemasPublish))
	if response := f.router.Do(t, staff, "POST", "/api/v1/schemas/neoworks/another/versions", publishBody("1.0.0"), nil); response.Code != http.StatusCreated {
		t.Fatalf("a Neoworks member with schemas.publish publishes: %d %s", response.Code, response.Body.String())
	}
}

func TestMembersNeedSchemasPublishForTheOrganizationsScope(t *testing.T) {
	f := newFixture(t)
	f.organizationWith("acme", "founder")
	publisher := f.addMember("acme", ownership.OrganizationWide(ownership.SchemasPublish))
	editor := f.addMember("acme", ownership.OrganizationWide(ownership.AppsCreate), ownership.OrganizationWide(ownership.AuditView))
	path := "/api/v1/schemas/acme/commerce"

	refused := f.expectProblem(editor, "POST", path+"/versions", publishBody("1.0.0"), http.StatusForbidden, "missing_permission")
	if refused.Permission != string(ownership.SchemasPublish) {
		t.Fatalf("the refusal must name schemas.publish: %+v", refused)
	}
	if response := f.router.Do(t, publisher, "POST", path+"/versions", publishBody("1.0.0"), nil); response.Code != http.StatusCreated {
		t.Fatalf("member with schemas.publish: %d %s", response.Code, response.Body.String())
	}
	f.expectProblem(editor, "GET", path+"/publishes", nil, http.StatusForbidden, "missing_permission")
	if response := f.router.Do(t, publisher, "GET", path+"/publishes", nil, nil); response.Code != http.StatusOK {
		t.Fatalf("member with schemas.publish reads the publishes: %d", response.Code)
	}
}

func TestNobodyPublishesIntoAnArchivedOrganization(t *testing.T) {
	f := newFixture(t)
	leader := f.organizationWith("acme", "founder")
	f.router.Do(t, leader, "POST", "/api/v1/schemas/acme/commerce/versions", publishBody("1.0.0"), nil)
	if err := f.store.ArchiveOrganization(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	f.expectProblem(leader, "POST", "/api/v1/schemas/acme/commerce/versions", publishBody("1.1.0"), http.StatusConflict, "archived")
	if response := f.router.DoAnonymous(t, "GET", "/api/v1/schemas/acme/commerce"); response.Code != http.StatusOK {
		t.Fatalf("archived organizations keep their schemas readable: %d", response.Code)
	}
}

func TestListingFiltersByScope(t *testing.T) {
	f := newFixture(t)
	acme := f.publisher(t, "acme")
	other := f.publisher(t, "other")
	f.router.Do(t, acme, "POST", "/api/v1/schemas/acme/commerce/versions", publishBody("1.0.0"), nil)
	f.router.Do(t, other, "POST", "/api/v1/schemas/other/commerce/versions", publishBody("1.0.0"), nil)

	for query, wanted := range map[string]int{"?scope=acme": 1, "?scope=nobody": 0, "?scope=acme&q=commerce": 1, "?scope=other&q=identity": 0} {
		var listed struct {
			Schemas []struct {
				Scope string `json:"scope"`
			} `json:"schemas"`
		}
		handlertest.Decode(t, f.router.DoAnonymous(t, "GET", "/api/v1/schemas"+query), &listed)
		if len(listed.Schemas) != wanted {
			t.Errorf("listing %q: got %d schemas want %d", query, len(listed.Schemas), wanted)
		}
	}
}
