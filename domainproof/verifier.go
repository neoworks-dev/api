package domainproof

import (
	"context"
	"log/slog"
	"time"

	"github.com/neoworks/auth/storage/database"
)

const (
	checkTimeout = 10 * time.Second
	// RevokeAfterFailedChecks is how many failed checks in a row take the
	// verification from a verified domain.
	RevokeAfterFailedChecks = 3
)

// Verifier checks a domain's proof, stores the outcome and keeps the
// verification of the owner's apps in step with it.
type Verifier struct {
	store  *database.SurrealStore
	prover Prover
}

func NewVerifier(store *database.SurrealStore, prover Prover) *Verifier {
	return &Verifier{store: store, prover: prover}
}

// Check looks the proof up now. A proof that cannot be found, or a lookup that
// fails, is a failed check, not an error; an error is returned for storage
// problems and database.ErrDomainTaken.
func (verifier *Verifier) Check(ctx context.Context, handle string, domain database.OwnerDomain) (*database.DomainCheck, error) {
	checkContext, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	passed, err := Check(checkContext, verifier.prover, domain.Method, domain.Domain, domain.Token)
	if err != nil {
		slog.Info("domain proof not found", "domain", domain.Domain, "reason", err)
	}
	check, err := verifier.store.RecordDomainCheck(ctx, handle, domain.Domain, passed, RevokeAfterFailedChecks)
	if err != nil {
		return nil, err
	}
	if check.Domain.Verified != domain.Verified {
		_, err = verifier.store.RefreshOwnerVerification(ctx, handle)
	}
	return check, err
}
