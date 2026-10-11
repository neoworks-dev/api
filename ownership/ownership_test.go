package ownership_test

import (
	"testing"

	"github.com/neoworks/auth/ownership"
)

func TestHandleRules(t *testing.T) {
	cases := map[string]ownership.HandleProblem{
		"moritz":       "",
		"acme-labs":    "",
		"a1":           "",
		"a":            ownership.HandleInvalid,
		"-acme":        ownership.HandleInvalid,
		"Acme":         ownership.HandleInvalid,
		"acme_labs":    ownership.HandleInvalid,
		"neoworks":     ownership.HandleReserved,
		"neoworks-dev": ownership.HandleReserved,
		"openschema":   ownership.HandleReserved,
		"example":      "",
	}
	for handle, want := range cases {
		if got := ownership.CheckHandle(handle); got != want {
			t.Errorf("%q: got %q want %q", handle, got, want)
		}
	}
	if ownership.CheckHandle("a234567890123456789012345678901234567890") != ownership.HandleInvalid {
		t.Error("40 characters must be refused")
	}
}

func TestReach(t *testing.T) {
	organizationWide := ownership.OrganizationWide(ownership.AppsEdit)
	songs := ownership.ForApp(ownership.AppsEdit, "songs")
	if !organizationWide.Covers(songs) || songs.Covers(organizationWide) {
		t.Fatal("an organization-wide grant covers one app, not the reverse")
	}
	if songs.Covers(ownership.ForApp(ownership.AppsEdit, "photos")) {
		t.Fatal("a grant for one app does not cover another")
	}
	grants := []ownership.Grant{songs}
	if !ownership.Allows(grants, ownership.AppsEdit, "songs") || ownership.Allows(grants, ownership.AppsEdit, "") {
		t.Fatal("Allows follows reach")
	}
	if ownership.ForApp(ownership.MembersManage, "songs").IsValid() {
		t.Fatal("organization-only permissions cannot name an app")
	}
	if (ownership.Grant{Permission: "apps.everything"}).IsValid() {
		t.Fatal("unknown permissions are invalid")
	}
}

func TestNormalizeKeepsTheWidestGrants(t *testing.T) {
	grants := []ownership.Grant{
		ownership.ForApp(ownership.AppsEdit, "songs"),
		ownership.OrganizationWide(ownership.AppsEdit),
		ownership.OrganizationWide(ownership.AppsEdit),
		ownership.ForApp(ownership.UsageView, "songs"),
	}
	normalized := ownership.Normalize(grants)
	if len(normalized) != 2 {
		t.Fatalf("got %+v", normalized)
	}
}

func TestGrantChanges(t *testing.T) {
	manager := ownership.AllGrants()
	songsMaintainer := []ownership.Grant{
		ownership.OrganizationWide(ownership.MembersManage),
		ownership.ForApp(ownership.AppsEdit, "songs"),
	}
	members := map[string][]ownership.Grant{"owner": manager, "maintainer": songsMaintainer, "viewer": {}}

	change := func(actor []ownership.Grant, memberID string, after []ownership.Grant) ownership.ChangeProblem {
		return ownership.CheckGrantChange(ownership.GrantChange{
			ActorGrants: actor, Before: members[memberID], After: after, MemberID: memberID, Members: members,
		})
	}

	if got := change(songsMaintainer, "viewer", []ownership.Grant{ownership.ForApp(ownership.AppsEdit, "songs")}); got != "" {
		t.Errorf("granting what the actor holds: %q", got)
	}
	if got := change(songsMaintainer, "viewer", []ownership.Grant{ownership.OrganizationWide(ownership.AppsEdit)}); got != ownership.ProblemEscalation {
		t.Errorf("widening reach: %q", got)
	}
	if got := change(songsMaintainer, "owner", nil); got != ownership.ProblemEscalation {
		t.Errorf("removing grants the actor does not hold: %q", got)
	}
	if got := change(nil, "viewer", nil); got != ownership.ProblemMissingPermission {
		t.Errorf("without members.manage: %q", got)
	}
	if got := change(manager, "viewer", []ownership.Grant{ownership.ForApp(ownership.AuditView, "songs")}); got != ownership.ProblemInvalidGrant {
		t.Errorf("organization-only permission for an app: %q", got)
	}

	soleManager := map[string][]ownership.Grant{"owner": manager, "viewer": {}}
	demote := ownership.CheckGrantChange(ownership.GrantChange{
		ActorGrants: manager, Before: manager, After: nil, MemberID: "owner", Members: soleManager,
	})
	if demote != ownership.ProblemLastManager {
		t.Errorf("demoting the last manager: %q", demote)
	}
	if ownership.CheckLeave(soleManager, "owner") != ownership.ProblemLastManager {
		t.Error("the last manager cannot leave")
	}
	if ownership.CheckLeave(members, "owner") != "" {
		t.Error("another manager remains")
	}
}

func TestInvitationsCannotOfferMoreThanTheInviterHolds(t *testing.T) {
	inviter := []ownership.Grant{ownership.OrganizationWide(ownership.MembersManage), ownership.ForApp(ownership.UsageView, "songs")}
	if got := ownership.CheckGrantsToInvite("acme", inviter, []ownership.Grant{ownership.ForApp(ownership.UsageView, "songs")}); got != "" {
		t.Errorf("offering a held grant: %q", got)
	}
	if got := ownership.CheckGrantsToInvite("acme", inviter, []ownership.Grant{ownership.OrganizationWide(ownership.SchemasPublish)}); got != ownership.ProblemEscalation {
		t.Errorf("offering more: %q", got)
	}
}

func TestPlatformAdminExistsOnlyInTheNeoworksOrganization(t *testing.T) {
	admin := []ownership.Grant{ownership.OrganizationWide(ownership.MembersManage), ownership.OrganizationWide(ownership.PlatformAdmin)}
	offered := []ownership.Grant{ownership.OrganizationWide(ownership.PlatformAdmin)}
	if got := ownership.CheckGrantsToInvite("neoworks", admin, offered); got != "" {
		t.Errorf("platform.admin in neoworks: %q", got)
	}
	if got := ownership.CheckGrantsToInvite("acme", admin, offered); got != ownership.ProblemInvalidGrant {
		t.Errorf("platform.admin in another organization: %q", got)
	}
	if ownership.Allows(ownership.AllGrants(), ownership.PlatformAdmin, "") {
		t.Error("platform.admin must not be part of AllGrants")
	}
	if (ownership.Grant{Permission: ownership.PlatformAdmin, AppID: stringPointer("songs")}).IsValid() {
		t.Error("platform.admin cannot be limited to an app")
	}
}

func stringPointer(value string) *string { return &value }
