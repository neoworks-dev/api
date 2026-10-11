package organizations_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/handlers/handlertest"
	"github.com/neoworks/auth/handlers/organizations"
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
	handler := organizations.NewHandler(store)
	router := handlertest.NewAuthenticated(func(router chi.Router) { handler.RegisterAuthenticated(router) })
	return &fixture{t: t, store: store, router: router}
}

// expect sends a request and fails unless the response has the status and,
// when given, the error code.
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

// userWithHandle creates a user who picked the handle.
func (f *fixture) userWithHandle(handle string) access.Principal {
	user := handlertest.CreateUser(f.t, f.store)
	f.expect(user, "PUT", "/api/v1/me/handle", map[string]string{"handle": handle}, http.StatusOK, "")
	return user
}

func (f *fixture) emailOf(user access.Principal) string {
	stored, err := f.store.GetUserByID(context.Background(), user.UserID)
	if err != nil {
		f.t.Fatal(err)
	}
	return stored.Email
}

// join invites the user by email with the grants and accepts.
func (f *fixture) join(inviter access.Principal, organization string, user access.Principal, grants []ownership.Grant) {
	f.t.Helper()
	invitation := f.expect(inviter, "POST", "/api/v1/organizations/"+organization+"/invitations",
		map[string]any{"email": f.emailOf(user), "grants": grants}, http.StatusCreated, "")
	f.expect(user, "POST", "/api/v1/me/invitations/"+invitation["id"].(string)+"/accept", nil, http.StatusNoContent, "")
}

func TestHandlesArePickedOnceAndNeverShared(t *testing.T) {
	f := newFixture(t)
	user := handlertest.CreateUser(t, f.store)
	other := handlertest.CreateUser(t, f.store)

	if got := f.expect(user, "GET", "/api/v1/me/handle", nil, http.StatusOK, ""); got["handle"] != nil {
		t.Fatalf("a new user has no handle: %v", got)
	}
	f.expect(user, "PUT", "/api/v1/me/handle", map[string]string{"handle": "Bad_Handle"}, http.StatusBadRequest, "invalid_handle")
	f.expect(user, "PUT", "/api/v1/me/handle", map[string]string{"handle": "neoworks-team"}, http.StatusConflict, "handle_taken")
	f.expect(user, "PUT", "/api/v1/me/handle", map[string]string{"handle": "moritz"}, http.StatusOK, "")
	f.expect(user, "PUT", "/api/v1/me/handle", map[string]string{"handle": "moritz2"}, http.StatusConflict, "handle_already_set")
	f.expect(other, "PUT", "/api/v1/me/handle", map[string]string{"handle": "moritz"}, http.StatusConflict, "handle_taken")
	f.expect(other, "PUT", "/api/v1/me/handle", map[string]string{"handle": "neoworks"}, http.StatusConflict, "handle_taken")

	availability := f.expect(other, "GET", "/api/v1/handles/moritz/availability", nil, http.StatusOK, "")
	if availability["available"] != false || availability["reason"] != "taken" {
		t.Fatalf("taken handle: %v", availability)
	}
	if free := f.expect(other, "GET", "/api/v1/handles/someone-else/availability", nil, http.StatusOK, ""); free["available"] != true {
		t.Fatalf("free handle: %v", free)
	}
}

func TestCreatingAnOrganizationNeedsAHandleAndGivesEveryPermission(t *testing.T) {
	f := newFixture(t)
	nameless := handlertest.CreateUser(t, f.store)
	f.expect(nameless, "POST", "/api/v1/organizations", map[string]string{"handle": "acme", "displayName": "Acme"},
		http.StatusConflict, "handle_required")

	creator := f.userWithHandle("moritz")
	f.expect(creator, "POST", "/api/v1/organizations", map[string]string{"handle": "moritz", "displayName": "Acme"},
		http.StatusConflict, "handle_taken")
	created := f.expect(creator, "POST", "/api/v1/organizations", map[string]string{"handle": "acme", "displayName": "Acme"},
		http.StatusCreated, "")
	if created["kind"] != "organization" || len(created["myGrants"].([]any)) != len(ownership.AllPermissions) {
		t.Fatalf("created: %v", created)
	}

	var owners struct {
		Owners []database.OwnerMembership `json:"owners"`
	}
	handlertest.Decode(t, f.router.Do(t, creator, "GET", "/api/v1/me/owners", nil, nil), &owners)
	if len(owners.Owners) != 2 || owners.Owners[0].Owner.Handle != "moritz" || owners.Owners[1].Owner.Handle != "acme" {
		t.Fatalf("owners: %+v", owners)
	}

	stranger := f.userWithHandle("stranger")
	f.expect(stranger, "GET", "/api/v1/organizations/acme", nil, http.StatusNotFound, "not_found")
	f.expect(creator, "GET", "/api/v1/organizations/moritz", nil, http.StatusNotFound, "not_found")
	renamed := f.expect(creator, "PATCH", "/api/v1/organizations/acme", map[string]string{"displayName": "Acme Inc"}, http.StatusOK, "")
	if renamed["displayName"] != "Acme Inc" || renamed["handle"] != "acme" {
		t.Fatalf("renamed: %v", renamed)
	}
}

func TestMemberPermissionsFollowTheRules(t *testing.T) {
	f := newFixture(t)
	owner := f.userWithHandle("owner")
	f.expect(owner, "POST", "/api/v1/organizations", map[string]string{"handle": "acme", "displayName": "Acme"}, http.StatusCreated, "")
	maintainer := handlertest.CreateUser(t, f.store)
	viewer := handlertest.CreateUser(t, f.store)

	contactsApp := []ownership.Grant{ownership.OrganizationWide(ownership.MembersManage), ownership.ForApp(ownership.AppsEdit, "neoworks-contacts")}
	f.join(owner, "acme", maintainer, contactsApp)
	f.join(owner, "acme", viewer, nil)

	members := f.expect(owner, "GET", "/api/v1/organizations/acme/members", nil, http.StatusOK, "")
	if len(members["members"].([]any)) != 3 {
		t.Fatalf("members: %v", members)
	}

	viewerGrants := "/api/v1/organizations/acme/members/" + viewer.UserID + "/grants"
	f.expect(viewer, "PUT", viewerGrants, map[string]any{"grants": []ownership.Grant{}}, http.StatusForbidden, "missing_permission")
	f.expect(maintainer, "PUT", viewerGrants,
		map[string]any{"grants": []ownership.Grant{ownership.ForApp(ownership.AppsEdit, "neoworks-contacts")}}, http.StatusOK, "")
	f.expect(maintainer, "PUT", viewerGrants,
		map[string]any{"grants": []ownership.Grant{ownership.OrganizationWide(ownership.AppsEdit)}}, http.StatusForbidden, "escalation")
	f.expect(maintainer, "PUT", "/api/v1/organizations/acme/members/"+owner.UserID+"/grants",
		map[string]any{"grants": []ownership.Grant{}}, http.StatusForbidden, "escalation")
	f.expect(owner, "PUT", viewerGrants,
		map[string]any{"grants": []ownership.Grant{ownership.ForApp(ownership.AppsEdit, "no-such-app")}}, http.StatusBadRequest, "unknown_app")
	f.expect(owner, "PUT", viewerGrants,
		map[string]any{"grants": []ownership.Grant{ownership.ForApp(ownership.AuditView, "neoworks-contacts")}}, http.StatusBadRequest, "invalid_grant")

	f.expect(maintainer, "POST", "/api/v1/organizations/acme/invitations",
		map[string]any{"email": "new@example.com", "grants": []ownership.Grant{ownership.OrganizationWide(ownership.SchemasPublish)}},
		http.StatusForbidden, "escalation")

	f.expect(owner, "PUT", "/api/v1/organizations/acme/members/"+maintainer.UserID+"/grants",
		map[string]any{"grants": []ownership.Grant{}}, http.StatusOK, "")
	f.expect(owner, "PUT", "/api/v1/organizations/acme/members/"+owner.UserID+"/grants",
		map[string]any{"grants": []ownership.Grant{}}, http.StatusConflict, "last_members_manager")
	f.expect(owner, "DELETE", "/api/v1/organizations/acme/members/"+owner.UserID, nil, http.StatusConflict, "last_members_manager")

	f.expect(viewer, "DELETE", "/api/v1/organizations/acme/members/"+viewer.UserID, nil, http.StatusNoContent, "")
	f.expect(owner, "DELETE", "/api/v1/organizations/acme/members/"+maintainer.UserID, nil, http.StatusNoContent, "")
	f.expect(maintainer, "GET", "/api/v1/organizations/acme", nil, http.StatusNotFound, "not_found")
}

func TestInvitationsReachOnlyTheirInvitee(t *testing.T) {
	f := newFixture(t)
	owner := f.userWithHandle("owner")
	f.expect(owner, "POST", "/api/v1/organizations", map[string]string{"handle": "acme", "displayName": "Acme"}, http.StatusCreated, "")
	invitee := handlertest.CreateUser(t, f.store)
	bystander := handlertest.CreateUser(t, f.store)
	code, err := f.store.GetContactCode(context.Background(), invitee.UserID)
	if err != nil {
		t.Fatal(err)
	}

	f.expect(owner, "POST", "/api/v1/organizations/acme/invitations", map[string]any{"contactCode": "0000-0000-0000"},
		http.StatusBadRequest, "unknown_contact_code")
	f.expect(owner, "POST", "/api/v1/organizations/acme/invitations", map[string]any{"email": "not-an-email"},
		http.StatusBadRequest, "invalid_invitee")
	invitation := f.expect(owner, "POST", "/api/v1/organizations/acme/invitations",
		map[string]any{"contactCode": code, "grants": []ownership.Grant{ownership.OrganizationWide(ownership.AuditView)}}, http.StatusCreated, "")
	invitationID := invitation["id"].(string)

	if listed := f.expect(bystander, "GET", "/api/v1/me/invitations", nil, http.StatusOK, ""); len(listed["invitations"].([]any)) != 0 {
		t.Fatalf("a bystander sees no invitations: %v", listed)
	}
	f.expect(bystander, "POST", "/api/v1/me/invitations/"+invitationID+"/accept", nil, http.StatusNotFound, "not_found")
	received := f.expect(invitee, "GET", "/api/v1/me/invitations", nil, http.StatusOK, "")
	if len(received["invitations"].([]any)) != 1 {
		t.Fatalf("the invitee sees it: %v", received)
	}
	f.expect(invitee, "POST", "/api/v1/me/invitations/"+invitationID+"/accept", nil, http.StatusNoContent, "")

	audit := f.expect(invitee, "GET", "/api/v1/organizations/acme/audit?limit=2", nil, http.StatusOK, "")
	entries := audit["entries"].([]any)
	if len(entries) != 2 || entries[0].(map[string]any)["action"] != database.AuditInvitationAccepted || audit["nextCursor"] == nil {
		t.Fatalf("audit page: %v", audit)
	}
	rest := f.expect(invitee, "GET", "/api/v1/organizations/acme/audit?before="+audit["nextCursor"].(string), nil, http.StatusOK, "")
	if len(rest["entries"].([]any)) != 1 {
		t.Fatalf("second audit page: %v", rest)
	}
}

func TestArchivedOrganizationsKeepTheirHandle(t *testing.T) {
	f := newFixture(t)
	owner := f.userWithHandle("owner")
	f.expect(owner, "POST", "/api/v1/organizations", map[string]string{"handle": "acme", "displayName": "Acme"}, http.StatusCreated, "")
	archived := f.expect(owner, "POST", "/api/v1/organizations/acme/archive", nil, http.StatusOK, "")
	if archived["archivedAt"] == nil {
		t.Fatalf("archived: %v", archived)
	}
	f.expect(owner, "PATCH", "/api/v1/organizations/acme", map[string]string{"displayName": "New"}, http.StatusConflict, "archived")
	f.expect(owner, "POST", "/api/v1/organizations/acme/invitations", map[string]any{"email": "a@example.com"}, http.StatusConflict, "archived")
	if available := f.expect(owner, "GET", "/api/v1/handles/acme/availability", nil, http.StatusOK, ""); available["available"] != false {
		t.Fatalf("an archived organization's handle stays taken: %v", available)
	}
	other := f.userWithHandle("other")
	f.expect(other, "POST", "/api/v1/organizations", map[string]string{"handle": "acme", "displayName": "Acme 2"}, http.StatusConflict, "handle_taken")
}
