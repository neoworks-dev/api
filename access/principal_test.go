package access_test

import (
	"slices"
	"testing"

	"github.com/neoworks/auth/access"
)

func TestRolesUsableAreCappedByTheTokenScopes(t *testing.T) {
	readOnly := access.Principal{Scopes: []string{"calendar:read"}}
	readWrite := access.Principal{Scopes: []string{"calendar:write"}}
	none := access.Principal{Scopes: []string{"photos:write"}}

	cases := []struct {
		name      string
		principal access.Principal
		minimum   string
		want      []string
	}{
		{"read scope reads", readOnly, access.RoleRead, []string{"read", "write", "admin"}},
		{"read scope cannot write", readOnly, access.RoleWrite, []string{}},
		{"read scope cannot administer", readOnly, access.RoleAdmin, []string{}},
		{"write scope writes", readWrite, access.RoleWrite, []string{"write", "admin"}},
		{"write scope implies read", readWrite, access.RoleRead, []string{"read", "write", "admin"}},
		{"write scope can administer with an admin grant", readWrite, access.RoleAdmin, []string{"admin"}},
		{"other collection", none, access.RoleRead, []string{}},
	}
	for _, testCase := range cases {
		got := testCase.principal.RolesUsable("calendar", testCase.minimum)
		if !slices.Equal(got, testCase.want) {
			t.Errorf("%s: got %v want %v", testCase.name, got, testCase.want)
		}
	}
}

func TestGoogleNodesFollowTheCalendarScopes(t *testing.T) {
	calendar := access.Principal{Scopes: []string{"calendar:write"}}
	contacts := access.Principal{Scopes: []string{"contacts:write"}}
	if !calendar.CanRead("google") || !calendar.CanWrite("google") {
		t.Error("calendar scopes should cover google nodes")
	}
	if contacts.CanRead("google") {
		t.Error("contacts scopes must not cover google nodes")
	}
	if got := calendar.ReadableCollections(); !slices.Contains(got, "google") || !slices.Contains(got, "calendar") {
		t.Errorf("readable collections: %v", got)
	}
}

func TestPrincipalIsTheInstallWhenBound(t *testing.T) {
	account := access.Principal{UserID: "user-1"}
	app := access.Principal{UserID: "user-1", InstallID: "install-1"}
	if account.Type() != "user" || account.ID() != "user-1" {
		t.Errorf("account principal: %s %s", account.Type(), account.ID())
	}
	if app.Type() != "install" || app.ID() != "install-1" {
		t.Errorf("install principal: %s %s", app.Type(), app.ID())
	}
}
