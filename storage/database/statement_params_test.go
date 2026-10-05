package database

import (
	"regexp"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/accesslog"
)

// SurrealQL evaluates a parameter that was never bound as NONE instead of
// failing, so a missing binding silently changes what a statement does. These
// tests list the parameters each statement names and require every one to be
// bound, defined with LET or FOR, a closure argument, or a built-in.

var (
	parameterPattern  = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)`)
	definitionPattern = regexp.MustCompile(`(?:LET|FOR|\|)\s*\$([A-Za-z_][A-Za-z0-9_]*)`)
	builtInParameters = map[string]bool{"before": true, "after": true, "value": true, "this": true, "event": true}
)

func unboundParameters(statement string, bound map[string]any, guarded ...string) []string {
	defined := map[string]bool{}
	for name := range bound {
		defined[name] = true
	}
	for _, name := range guarded {
		defined[name] = true
	}
	for _, match := range definitionPattern.FindAllStringSubmatch(statement, -1) {
		defined[match[1]] = true
	}
	missing := map[string]bool{}
	for _, match := range parameterPattern.FindAllStringSubmatch(statement, -1) {
		if !defined[match[1]] && !builtInParameters[match[1]] {
			missing[match[1]] = true
		}
	}
	names := make([]string, 0, len(missing))
	for name := range missing {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// requireAllBound fails when the statement names a parameter that is neither
// bound nor in guarded, the parameters the statement only reads behind a flag.
func requireAllBound(t *testing.T, name, statement string, bound map[string]any, guarded ...string) {
	t.Helper()
	if missing := unboundParameters(statement, bound, guarded...); len(missing) > 0 {
		t.Errorf("%s names parameters that are never bound: %v", name, missing)
	}
}

func TestPushStatementBindsEveryParameter(t *testing.T) {
	owner := access.Principal{UserID: uuid.NewString(), Scopes: []string{"files:write"}}
	parent := uuid.NewString()
	wrapped, cert := "wrapped", uuid.NewString()
	blobJSON := `{"objectId":"` + uuid.NewString() + `","chunks":1,"size":1}`
	variants := map[string]Node{
		"root": {ID: uuid.NewString(), OwnerID: owner.UserID, Collection: "files", Kind: KindRoot, Epoch: 1,
			AuthorType: "user", AuthorID: owner.UserID, Signature: "s"},
		"item with blob and cert": {ID: uuid.NewString(), ParentID: &parent, OwnerID: owner.UserID, Collection: "files",
			Kind: KindItem, Epoch: 1, WrappedKey: &wrapped, CertID: &cert, Blob: []byte(blobJSON),
			AuthorType: "user", AuthorID: owner.UserID, Signature: "s"},
		"plain item": {ID: uuid.NewString(), ParentID: &parent, OwnerID: owner.UserID, Collection: "files",
			Kind: KindItem, Epoch: 1, WrappedKey: &wrapped, AuthorType: "user", AuthorID: owner.UserID, Signature: "s"},
	}
	for name, node := range variants {
		validated := &ValidatedNode{Node: node, BlobObjects: []string{}}
		if len(node.Blob) > 0 {
			validated.BlobJSON = &blobJSON
			validated.BlobObject = map[string]any{"objectId": "x"}
		}
		params := pushParams(owner, validated, []string{"write", "admin"})
		requireAllBound(t, "push "+name, pushStatement(validated), params, "parent", "parent_id")
	}
}

func TestGrantStatementsBindEveryParameter(t *testing.T) {
	node := &dbNode{Collection: "calendar"}
	entry := accesslog.Entry{Action: accesslog.ActionGrant, Role: "read", Epoch: 1}
	for name, input := range map[string]GrantInput{
		"whole node": {PrincipalType: "user", PrincipalID: uuid.NewString(), Role: "read", Epoch: 1, WrappedKeys: "k"},
		"facets":     {PrincipalType: "user", PrincipalID: uuid.NewString(), Role: "read", Facets: []int{1}, Epoch: 1, WrappedKeys: "k"},
	} {
		entry.Facets = input.Facets
		params := grantParams(uuid.NewString(), node, input, entry, "hash")
		requireAllBound(t, "grant "+name, grantStatement(input, false), params)
	}
	certID := uuid.NewString()
	installEntry := accesslog.Entry{Action: accesslog.ActionGrant, Role: "read", Epoch: 1, CertID: &certID}
	installInput := GrantInput{PrincipalType: "install", PrincipalID: uuid.NewString(), Role: "read", Epoch: 1, WrappedKeys: "k"}
	params := grantParams(uuid.NewString(), node, installInput, installEntry, "hash")
	requireAllBound(t, "grant to install", grantStatement(installInput, true), params)
}

func TestOtherStatementsBindEveryParameter(t *testing.T) {
	principal := access.Principal{UserID: uuid.NewString(), Scopes: []string{"calendar:read"}}
	requireAllBound(t, "pull", pullStatement, pullParams(principal, 0, 10))
	requireAllBound(t, "link pull", linkPullStatement, map[string]any{"node_id": "n", "cursor": 0, "fetch": 1})

	statement, params, err := rotationStatement(uuid.NewString(), 1, KeyBundle{Version: 2, PwhashSalt: "s"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireAllBound(t, "rotation", statement, params)
	withAuth := "auth"
	statement, params, err = rotationStatement(uuid.NewString(), 1, KeyBundle{Version: 2}, &withAuth)
	if err != nil {
		t.Fatal(err)
	}
	requireAllBound(t, "rotation with auth key", statement, params)

	requireAllBound(t, "user creation", userCreationStatement(true),
		withDeviceParams(userCreationParams(&CreateUserParams{UserID: "u"}, "h")))
	requireAllBound(t, "user creation without device", userCreationStatement(false),
		userCreationParams(&CreateUserParams{UserID: "u"}, "h"))
}

func withDeviceParams(params map[string]any) map[string]any {
	addDeviceParams(params, &RegisterDeviceParams{Name: "n", Kind: DeviceKindBrowser})
	return params
}

func TestRevokeStatementBindsEveryParameter(t *testing.T) {
	for _, facets := range []bool{false, true} {
		entry := accesslog.Entry{Action: accesslog.ActionRevoke, Role: "read", Epoch: 1}
		if facets {
			entry.Facets = []int{1}
		}
		params := entryParams("n", entry, "hash")
		params["collection"] = "calendar"
		requireAllBound(t, "revoke", revokeStatement(facets), params)
	}
}

func TestRegistryStatementsBindEveryParameter(t *testing.T) {
	input := RegistryPublishInput{Scope: "acme", Name: "commerce", Version: "1.0.0",
		Files: []RegistryPublishFile{{Path: "a.schema", Contents: "x"}}}
	requireAllBound(t, "registry publish", registryPublishStatement, registryPublishParams(uuid.NewString(), input))
	requireAllBound(t, "registry list", registryListStatement, map[string]any{"limit": 1})
	requireAllBound(t, "registry search", registrySearchStatement, map[string]any{"limit": 1, "query": "q"})
	requireAllBound(t, "registry get", registryGetStatement, map[string]any{"scope": "s", "name": "n"})
	requireAllBound(t, "registry versions", registryVersionsStatement, map[string]any{"schema": "s"})
	requireAllBound(t, "registry version", registryVersionStatement, map[string]any{"schema": "s", "version": "v"})
	requireAllBound(t, "registry files", registryFilesStatement, map[string]any{"version": "v"})
}
