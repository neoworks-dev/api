package apps_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/domainproof"
	"github.com/neoworks/auth/handlers/apps"
	"github.com/neoworks/auth/ownership"
	"github.com/neoworks/auth/storage/database"
)

// publishedProofs is what the fake internet serves: the token each domain
// publishes, for DNS and the well-known file alike.
type publishedProofs map[string]string

func (proofs publishedProofs) LookupTXT(_ context.Context, name string) ([]string, error) {
	token, found := proofs[name]
	if !found {
		return nil, errors.New("no such host")
	}
	return []string{"v=spf1 -all", token}, nil
}

func (proofs publishedProofs) FetchWellKnown(_ context.Context, domain string) (string, error) {
	token, found := proofs[domain]
	if !found {
		return "", errors.New("404")
	}
	return token + "\n", nil
}

func newDomainFixture(t *testing.T) (*fixture, publishedProofs) {
	proofs := publishedProofs{}
	return newFixtureWith(t, func(handler *apps.Handler) { handler.WithDomainProver(proofs) }), proofs
}

func (f *fixture) addDomain(principal access.Principal, owner string, domain string, method string) map[string]any {
	f.t.Helper()
	return f.expect(principal, "POST", "/api/v1/owners/"+owner+"/domains", map[string]any{"domain": domain, "method": method}, http.StatusCreated, "")
}

func (f *fixture) verifyDomain(principal access.Principal, owner string, domain string) map[string]any {
	f.t.Helper()
	return f.expect(principal, "POST", "/api/v1/owners/"+owner+"/domains/"+domain+"/verify", nil, http.StatusOK, "")
}

func (f *fixture) auditActions(organization string) []string {
	f.t.Helper()
	page, err := f.store.ListAudit(context.Background(), organization, zeroTime, 100)
	if err != nil {
		f.t.Fatalf("audit: %v", err)
	}
	actions := []string{}
	for _, entry := range page.Entries {
		actions = append(actions, entry.Action)
	}
	return actions
}

func (f *fixture) appVerified(principal access.Principal, clientID string) bool {
	f.t.Helper()
	return f.expect(principal, "GET", "/api/v1/apps/"+clientID, nil, http.StatusOK, "")["verified"] == true
}

func TestADomainIsAddedWithATokenAndVerifiedByItsProof(t *testing.T) {
	f, proofs := newDomainFixture(t)
	owner := f.userWithHandle("moritz")

	added := f.addDomain(owner, "moritz", "Recipes.Example.com", "dns")
	token := added["token"].(string)
	if added["domain"] != "recipes.example.com" || added["verified"] != false || len(token) < len(domainproof.TokenPrefix)+16 {
		t.Fatalf("added: %v", added)
	}
	failed := f.verifyDomain(owner, "moritz", "recipes.example.com")
	if failed["verified"] != false || failed["lastCheckedAt"] == nil {
		t.Fatalf("without the proof: %v", failed)
	}
	proofs["recipes.example.com"] = token
	passed := f.verifyDomain(owner, "moritz", "recipes.example.com")
	if passed["verified"] != true || passed["verifiedAt"] == nil {
		t.Fatalf("with the proof: %v", passed)
	}
	listed := f.expect(owner, "GET", "/api/v1/owners/moritz/domains", nil, http.StatusOK, "")["domains"].([]any)
	if len(listed) != 1 || listed[0].(map[string]any)["verified"] != true {
		t.Fatalf("list: %v", listed)
	}
}

func TestDomainInputIsValidated(t *testing.T) {
	f, _ := newDomainFixture(t)
	owner := f.userWithHandle("moritz")
	f.expect(owner, "POST", "/api/v1/owners/moritz/domains", map[string]any{"domain": "https://example.com", "method": "dns"}, http.StatusBadRequest, "invalid_request")
	f.expect(owner, "POST", "/api/v1/owners/moritz/domains", map[string]any{"domain": "example.com", "method": "carrier-pigeon"}, http.StatusBadRequest, "invalid_request")
	f.addDomain(owner, "moritz", "example.com", "wellKnown")
	f.expect(owner, "POST", "/api/v1/owners/moritz/domains", map[string]any{"domain": "example.com", "method": "dns"}, http.StatusConflict, "domain_exists")
	f.expect(owner, "POST", "/api/v1/owners/moritz/domains/other.example.com/verify", nil, http.StatusNotFound, "not_found")
}

func TestOnlyOneOwnerHoldsADomainVerified(t *testing.T) {
	f, proofs := newDomainFixture(t)
	first := f.userWithHandle("first")
	second := f.userWithHandle("second")
	token := f.addDomain(first, "first", "shared.example.com", "dns")["token"].(string)
	otherToken := f.addDomain(second, "second", "shared.example.com", "dns")["token"].(string)
	proofs["shared.example.com"] = token
	f.verifyDomain(first, "first", "shared.example.com")

	proofs["shared.example.com"] = otherToken
	f.expect(second, "POST", "/api/v1/owners/second/domains/shared.example.com/verify", nil, http.StatusConflict, "domain_taken")
}

func TestManagingDomainsNeedsDomainsManage(t *testing.T) {
	f, _ := newDomainFixture(t)
	leader := f.userWithHandle("founder")
	f.organization("acme", leader)
	viewer := f.member("acme", ownership.OrganizationWide(ownership.AuditView))
	stranger := f.userWithHandle("stranger")

	body := map[string]any{"domain": "acme.example", "method": "dns"}
	response := f.expect(viewer, "POST", "/api/v1/owners/acme/domains", body, http.StatusForbidden, "missing_permission")
	if response["permission"] != string(ownership.DomainsManage) {
		t.Fatalf("permission named: %v", response)
	}
	f.expect(viewer, "GET", "/api/v1/owners/acme/domains", nil, http.StatusOK, "")
	f.expect(stranger, "GET", "/api/v1/owners/acme/domains", nil, http.StatusNotFound, "")
	f.expect(stranger, "POST", "/api/v1/owners/acme/domains", body, http.StatusNotFound, "")
}

func TestAppsAreVerifiedWhenTheirURLsAreOnVerifiedDomains(t *testing.T) {
	f, proofs := newDomainFixture(t)
	owner := f.userWithHandle("moritz")
	app := appOf(f.createApp(owner, "moritz", map[string]any{
		"homepage": "https://www.recipes.example.com", "redirectUris": []string{"https://app.recipes.example.com/callback", "http://localhost:3000/cb"},
	}))
	clientID := app["id"].(string)
	if app["verified"] != false {
		t.Fatal("no verified domain yet")
	}

	token := f.addDomain(owner, "moritz", "recipes.example.com", "wellKnown")["token"].(string)
	proofs["recipes.example.com"] = token
	f.verifyDomain(owner, "moritz", "recipes.example.com")
	if !f.appVerified(owner, clientID) {
		t.Fatal("redirect URI and homepage are on the verified domain")
	}

	other := f.expect(owner, "PATCH", "/api/v1/apps/"+clientID, map[string]any{"homepage": "https://elsewhere.example.org"}, http.StatusOK, "")
	if other["verified"] != false {
		t.Fatalf("a homepage on another domain: %v", other)
	}
	back := f.expect(owner, "PATCH", "/api/v1/apps/"+clientID, map[string]any{"homepage": "https://recipes.example.com"}, http.StatusOK, "")
	if back["verified"] != true {
		t.Fatalf("homepage back on the domain: %v", back)
	}
	f.expect(owner, "DELETE", "/api/v1/owners/moritz/domains/recipes.example.com", nil, http.StatusNoContent, "")
	if f.appVerified(owner, clientID) {
		t.Fatal("removing the domain must unverify the app")
	}
}

func TestAppsWithOnlyLoopbackURLsAreNeverVerified(t *testing.T) {
	f, proofs := newDomainFixture(t)
	owner := f.userWithHandle("moritz")
	app := appOf(f.createApp(owner, "moritz", map[string]any{"homepage": "", "redirectUris": []string{"http://127.0.0.1:8080/cb"}}))
	token := f.addDomain(owner, "moritz", "recipes.example.com", "dns")["token"].(string)
	proofs["recipes.example.com"] = token
	f.verifyDomain(owner, "moritz", "recipes.example.com")
	if f.appVerified(owner, app["id"].(string)) {
		t.Fatal("an app without an https URL proves nothing")
	}
}

func TestAVerifiedDomainLosesItAfterRepeatedFailedChecks(t *testing.T) {
	f, proofs := newDomainFixture(t)
	owner := f.userWithHandle("moritz")
	clientID := appOf(f.createApp(owner, "moritz", nil))["id"].(string)
	token := f.addDomain(owner, "moritz", "recipes.example.com", "dns")["token"].(string)
	proofs["recipes.example.com"] = token
	f.verifyDomain(owner, "moritz", "recipes.example.com")
	if !f.appVerified(owner, clientID) {
		t.Fatal("app should be verified")
	}

	delete(proofs, "recipes.example.com")
	for check := 1; check < domainproof.RevokeAfterFailedChecks; check++ {
		if still := f.verifyDomain(owner, "moritz", "recipes.example.com"); still["verified"] != true {
			t.Fatalf("one failed check must not revoke (check %d)", check)
		}
	}
	revoked := f.verifyDomain(owner, "moritz", "recipes.example.com")
	if revoked["verified"] != false || f.appVerified(owner, clientID) {
		t.Fatalf("after %d failed checks: %v", domainproof.RevokeAfterFailedChecks, revoked)
	}
}

func TestDomainChangesAreAuditedForOrganizations(t *testing.T) {
	f, proofs := newDomainFixture(t)
	leader := f.userWithHandle("founder")
	f.organization("acme", leader)
	token := f.addDomain(leader, "acme", "acme.example", "dns")["token"].(string)
	proofs["acme.example"] = token
	f.verifyDomain(leader, "acme", "acme.example")
	f.expect(leader, "DELETE", "/api/v1/owners/acme/domains/acme.example", nil, http.StatusNoContent, "")

	got := f.auditActions("acme")
	want := []string{database.AuditDomainRemoved, database.AuditDomainVerified, database.AuditDomainAdded}
	if len(got) < len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("audit actions %v, want the domain entries %v first", got, want)
	}
}
