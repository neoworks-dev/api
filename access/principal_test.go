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
		{"read scope reads", readOnly, access.RoleRead, []string{"read", "write"}},
		{"read scope cannot write", readOnly, access.RoleWrite, []string{}},
		{"write scope writes", readWrite, access.RoleWrite, []string{"write"}},
		{"write scope implies read", readWrite, access.RoleRead, []string{"read", "write"}},
		{"other collection", none, access.RoleRead, []string{}},
	}
	for _, testCase := range cases {
		got := testCase.principal.RolesUsable("calendar", testCase.minimum)
		if !slices.Equal(got, testCase.want) {
			t.Errorf("%s: got %v want %v", testCase.name, got, testCase.want)
		}
	}
	if access.ValidRole("admin") {
		t.Error("admin is not a role")
	}
}

func TestGoogleNodesAreGatedByGoogleScopes(t *testing.T) {
	google := access.Principal{Scopes: []string{"google:write"}}
	calendar := access.Principal{Scopes: []string{"calendar:write"}}
	if !google.CanRead("google") || !google.CanWrite("google") {
		t.Error("google scopes should cover google nodes")
	}
	if calendar.CanRead("google") {
		t.Error("calendar scopes must not cover google nodes")
	}
	if google.CanRead("calendar") {
		t.Error("google scopes must not cover calendar nodes")
	}
	if got := google.ReadableCollections(); !slices.Equal(got, []string{"google"}) {
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
