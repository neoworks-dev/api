package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/neoworks/auth/domainproof"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
)

type servedProofs map[string]string

func (proofs servedProofs) LookupTXT(_ context.Context, name string) ([]string, error) {
	token, found := proofs[name]
	if !found {
		return nil, errors.New("no such host")
	}
	return []string{token}, nil
}

func (proofs servedProofs) FetchWellKnown(context.Context, string) (string, error) {
	return "", errors.New("404")
}

func TestARecheckRevokesADomainThatStoppedServingItsProof(t *testing.T) {
	store := dbtest.New(t)
	ctx := context.Background()
	leader := dbtest.CreateAccount(t, store).Principal
	if err := store.ClaimUserHandle(ctx, leader.UserID, "founder"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateOrganization(ctx, leader.UserID, "acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	app, err := store.CreateApp(ctx, database.NewApp{
		ID: "app_" + uuid.NewString()[:8], OwnerHandle: "acme", CreatorID: leader.UserID, Type: database.AppTypePublic,
		Fields: database.AppFields{Name: "Acme", RedirectURIs: []string{"https://app.acme.example/cb"}, Scopes: []database.RequestedScope{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	token := "neoworks-verify=abc"
	if _, err := store.AddDomain(ctx, "acme", "acme.example", database.DomainMethodDNS, token); err != nil {
		t.Fatal(err)
	}
	proofs := servedProofs{"acme.example": token}
	rechecker := NewDomainRechecker(store, domainproof.NewVerifier(store, proofs))
	if _, err := rechecker.verifier.Check(ctx, "acme", database.OwnerDomain{Domain: "acme.example", Method: database.DomainMethodDNS, Token: token}); err != nil {
		t.Fatal(err)
	}
	if verified := appVerified(t, store, app.ID); !verified {
		t.Fatal("the app is verified once the proof is found")
	}

	rechecker.now = func() time.Time { return time.Now().Add(recheckAge + time.Hour) }
	rechecker.RunOnce(ctx)
	if domain, _ := store.GetDomain(ctx, "acme", "acme.example"); !domain.Verified {
		t.Fatal("a passing re-check keeps the verification")
	}

	delete(proofs, "acme.example")
	for run := 1; run <= domainproof.RevokeAfterFailedChecks; run++ {
		rechecker.RunOnce(ctx)
	}
	if domain, _ := store.GetDomain(ctx, "acme", "acme.example"); domain.Verified {
		t.Fatal("repeated failures revoke the verification")
	}
	if appVerified(t, store, app.ID) {
		t.Fatal("the app on the revoked domain is no longer verified")
	}
	page, err := store.ListAudit(ctx, "acme", time.Time{}, 10)
	if err != nil || len(page.Entries) == 0 || page.Entries[0].Action != database.AuditDomainRevoked || page.Entries[0].Actor.DisplayName != "Neoworks" {
		t.Fatalf("audit: %+v %v", page, err)
	}
}

func appVerified(t *testing.T, store *database.SurrealStore, clientID string) bool {
	t.Helper()
	app, err := store.GetApp(context.Background(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	return app.Verified
}
