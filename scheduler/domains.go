package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/neoworks/auth/domainproof"
	"github.com/neoworks/auth/storage/database"
)

const (
	recheckInterval = time.Hour
	// recheckAge is how long a verified domain goes without a check.
	recheckAge   = 24 * time.Hour
	recheckBatch = 100
)

// DomainRechecker checks verified domains again, so an owner that stops serving
// its proof loses the verification of the domain and of the apps on it.
type DomainRechecker struct {
	store    *database.SurrealStore
	verifier *domainproof.Verifier
	now      func() time.Time
}

func NewDomainRechecker(store *database.SurrealStore, verifier *domainproof.Verifier) *DomainRechecker {
	return &DomainRechecker{store: store, verifier: verifier, now: time.Now}
}

// Start runs the job once an hour until ctx ends.
func (rechecker *DomainRechecker) Start(ctx context.Context) {
	go rechecker.run(ctx)
}

func (rechecker *DomainRechecker) run(ctx context.Context) {
	ticker := time.NewTicker(recheckInterval)
	defer ticker.Stop()
	for waitForTick(ctx, ticker) {
		rechecker.RunOnce(ctx)
	}
}

// RunOnce checks the verified domains that are due.
func (rechecker *DomainRechecker) RunOnce(ctx context.Context) {
	due, err := rechecker.store.ListVerifiedDomainsCheckedBefore(ctx, rechecker.now().Add(-recheckAge), recheckBatch)
	if err != nil {
		slog.Error("list domains to re-check", "error", err)
		return
	}
	for _, domain := range due {
		rechecker.recheck(ctx, domain)
	}
}

func (rechecker *DomainRechecker) recheck(ctx context.Context, due database.VerifiedDomain) {
	current := database.OwnerDomain{Domain: due.Domain, Method: due.Method, Token: due.Token, Verified: true}
	check, err := rechecker.verifier.Check(ctx, due.OwnerHandle, current)
	if err != nil {
		slog.Error("re-check domain", "owner", due.OwnerHandle, "domain", due.Domain, "error", err)
		return
	}
	if check.Revoked {
		slog.Info("domain lost its verification", "owner", due.OwnerHandle, "domain", due.Domain)
		rechecker.auditRevoked(ctx, due)
	}
}

// auditRevoked records the revocation in the audit log of an organization; the
// system is the actor. People have no audit log.
func (rechecker *DomainRechecker) auditRevoked(ctx context.Context, due database.VerifiedDomain) {
	owner, err := rechecker.store.GetOwner(ctx, due.OwnerHandle)
	if err != nil || owner.Kind != database.OwnerKindOrganization {
		return
	}
	err = rechecker.store.RecordAudit(ctx, database.AuditInput{
		Organization: due.OwnerHandle, Action: database.AuditDomainRevoked,
		Target:  database.AuditTarget{Kind: "domain", ID: due.Domain, Label: due.Domain},
		Details: map[string]any{"method": due.Method, "reason": "the proof was not found in repeated checks"},
	})
	if err != nil {
		slog.Error("record domain revocation", "owner", due.OwnerHandle, "error", err)
	}
}
