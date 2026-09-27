package oauth

import "testing"

// AllowsScopeLabel is the server-side half of the scope gate; it MUST agree with
// decryptableLabels in scope-keys.js or the API and the Vault would disagree on
// what a token can read. These cases mirror tests/scope-keys.test.ts.
func TestAllowsScopeLabel(t *testing.T) {
	claims := &Claims{Scope: []string{
		"openid",
		"profile",
		"photos:read",
		"contacts:write",
		"calendar:admin",
		"billing:create",
		"audit:delete",
		"org_1:documents:*",
	}}

	allowed := []string{"photos", "contacts", "calendar", "org_1:documents"}
	for _, label := range allowed {
		if !claims.AllowsScopeLabel(label) {
			t.Errorf("expected label %q to be allowed", label)
		}
	}

	denied := []string{"billing", "audit", "secrets", "openid", "profile"}
	for _, label := range denied {
		if claims.AllowsScopeLabel(label) {
			t.Errorf("expected label %q to be denied", label)
		}
	}
}

func TestAllowsScopeLabelLegacy(t *testing.T) {
	// The empty label is the legacy keyspace, gated by legacy:read.
	withLegacy := &Claims{Scope: []string{"legacy:read", "photos:read"}}
	if !withLegacy.AllowsScopeLabel("") {
		t.Error("legacy:read should permit the empty (legacy) label")
	}

	withoutLegacy := &Claims{Scope: []string{"photos:read"}}
	if withoutLegacy.AllowsScopeLabel("") {
		t.Error("a token without legacy:read must not read legacy objects")
	}
}

func TestAllowsScopeLabelEmptyClaims(t *testing.T) {
	none := &Claims{}
	if none.AllowsScopeLabel("photos") || none.AllowsScopeLabel("") {
		t.Error("a token with no scopes must decrypt nothing")
	}
}

// AllowsScopeWrite MUST agree with writableLabels in scope-keys.js: the spaces
// push handler relies on it to refuse writes from read-only clients.
func TestAllowsScopeWrite(t *testing.T) {
	claims := &Claims{Scope: []string{
		"openid",
		"photos:read",
		"contacts:write",
		"calendar:admin",
		"org_1:documents:*",
	}}

	allowed := []string{"contacts", "calendar", "org_1:documents"}
	for _, label := range allowed {
		if !claims.AllowsScopeWrite(label) {
			t.Errorf("expected write to label %q to be allowed", label)
		}
	}

	denied := []string{"photos", "memories", "openid", "", "legacy"}
	for _, label := range denied {
		if claims.AllowsScopeWrite(label) {
			t.Errorf("expected write to label %q to be denied", label)
		}
	}
}
