package apps_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/neoworks/auth/ownership"
	"github.com/neoworks/auth/storage/database"
)

func reviewBody() map[string]any {
	return map[string]any{"privacyPolicyUrl": "https://recipes.example.com/privacy", "supportContact": "support@recipes.example.com"}
}

func (f *fixture) decide(clientID string, decision database.ReviewDecision, reason string) {
	f.t.Helper()
	if _, err := f.store.DecideReview(context.Background(), clientID, decision, reason); err != nil {
		f.t.Fatalf("%s: %v", decision, err)
	}
}

func TestADeveloperSubmitsAnAppForReview(t *testing.T) {
	f := newFixture(t)
	owner := f.userWithHandle("moritz")
	clientID := appOf(f.createApp(owner, "moritz", nil))["id"].(string)

	review := f.expect(owner, "POST", "/api/v1/apps/"+clientID+"/review", reviewBody(), http.StatusOK, "")
	if review["status"] != "pending" || review["reason"] != nil || review["updatedAt"] == nil {
		t.Fatalf("review: %v", review)
	}
	app := f.expect(owner, "GET", "/api/v1/apps/"+clientID, nil, http.StatusOK, "")
	if app["reviewStatus"] != "pending" {
		t.Fatalf("summary status: %v", app["reviewStatus"])
	}
	f.expect(owner, "POST", "/api/v1/apps/"+clientID+"/review", reviewBody(), http.StatusConflict, "review_state")
}

func TestReviewNeedsADescribedAppAndValidContacts(t *testing.T) {
	f := newFixture(t)
	owner := f.userWithHandle("moritz")
	bare := appOf(f.createApp(owner, "moritz", map[string]any{"description": "", "homepage": ""}))["id"].(string)
	f.expect(owner, "POST", "/api/v1/apps/"+bare+"/review", reviewBody(), http.StatusBadRequest, "invalid_request")

	described := appOf(f.createApp(owner, "moritz", nil))["id"].(string)
	for _, body := range []map[string]any{
		{"privacyPolicyUrl": "http://insecure.example.com", "supportContact": "support@example.com"},
		{"privacyPolicyUrl": "https://example.com/privacy", "supportContact": "not an address"},
		{"privacyPolicyUrl": "https://example.com/privacy", "supportContact": ""},
	} {
		response := f.expect(owner, "POST", "/api/v1/apps/"+described+"/review", body, http.StatusBadRequest, "invalid_request")
		if response["field"] == nil {
			t.Fatalf("the rejected field is named: %v", response)
		}
	}
}

func TestSubmittingForReviewNeedsAppsReview(t *testing.T) {
	f := newFixture(t)
	leader := f.userWithHandle("founder")
	f.organization("acme", leader)
	clientID := appOf(f.createApp(leader, "acme", nil))["id"].(string)
	editor := f.member("acme", ownership.OrganizationWide(ownership.AppsEdit))
	reviewer := f.member("acme", ownership.ForApp(ownership.AppsReview, clientID))

	response := f.expect(editor, "POST", "/api/v1/apps/"+clientID+"/review", reviewBody(), http.StatusForbidden, "missing_permission")
	if response["permission"] != "apps.review" {
		t.Fatalf("permission named: %v", response)
	}
	f.expect(reviewer, "POST", "/api/v1/apps/"+clientID+"/review", reviewBody(), http.StatusOK, "")
	if actions := f.auditActions("acme"); actions[0] != database.AuditAppReviewSubmitted {
		t.Fatalf("audit: %v", actions)
	}
}

func TestTheDeveloperSeesTheReasonOfARejectionAndMayResubmit(t *testing.T) {
	f := newFixture(t)
	owner := f.userWithHandle("moritz")
	clientID := appOf(f.createApp(owner, "moritz", nil))["id"].(string)
	f.expect(owner, "POST", "/api/v1/apps/"+clientID+"/review", reviewBody(), http.StatusOK, "")
	f.decide(clientID, database.DecisionReject, "The privacy policy is empty.")

	app := f.expect(owner, "GET", "/api/v1/apps/"+clientID, nil, http.StatusOK, "")
	review := app["review"].(map[string]any)
	if review["status"] != "rejected" || review["reason"] != "The privacy policy is empty." {
		t.Fatalf("review: %v", review)
	}
	f.expect(owner, "POST", "/api/v1/apps/"+clientID+"/review", reviewBody(), http.StatusOK, "")
}

func TestWideningTheScopesOfAnApprovedAppSendsItBackToReview(t *testing.T) {
	f := newFixture(t)
	owner := f.userWithHandle("moritz")
	clientID := appOf(f.createApp(owner, "moritz", map[string]any{"scopes": []map[string]string{
		{"scope": "openid", "reason": "Sign in"}, {"scope": "email", "reason": "Contact"},
	}}))["id"].(string)
	f.expect(owner, "POST", "/api/v1/apps/"+clientID+"/review", reviewBody(), http.StatusOK, "")
	f.decide(clientID, database.DecisionApprove, "")

	narrower := f.expect(owner, "PATCH", "/api/v1/apps/"+clientID, map[string]any{
		"scopes": []map[string]string{{"scope": "openid", "reason": "Sign in"}},
	}, http.StatusOK, "")
	if narrower["reviewStatus"] != "approved" {
		t.Fatalf("asking for less keeps the approval: %v", narrower["reviewStatus"])
	}
	renamed := f.expect(owner, "PATCH", "/api/v1/apps/"+clientID, map[string]any{"name": "Recipes 2"}, http.StatusOK, "")
	if renamed["reviewStatus"] != "approved" {
		t.Fatalf("other edits keep the approval: %v", renamed["reviewStatus"])
	}
	wider := f.expect(owner, "PATCH", "/api/v1/apps/"+clientID, map[string]any{
		"scopes": []map[string]string{{"scope": "openid", "reason": "Sign in"}, {"scope": "profile", "reason": "Show your name"}},
	}, http.StatusOK, "")
	if wider["reviewStatus"] != "pending" || wider["review"].(map[string]any)["status"] != "pending" {
		t.Fatalf("asking for more goes back to review: %v", wider["review"])
	}
}
