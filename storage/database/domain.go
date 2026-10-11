package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/surrealdb/surrealdb.go/pkg/models"
)

const (
	DomainMethodDNS       = "dns"
	DomainMethodWellKnown = "wellKnown"
)

var (
	// ErrDomainExists means the owner already added the domain.
	ErrDomainExists = errors.New("domain already added")
	// ErrDomainTaken means another owner holds the domain verified.
	ErrDomainTaken = errors.New("domain verified by another owner")
)

// OwnerDomain is a domain an owner proves control of. Token is the value to
// publish as the proof.
type OwnerDomain struct {
	Domain        string     `json:"domain"`
	Method        string     `json:"method"`
	Token         string     `json:"token"`
	Verified      bool       `json:"verified"`
	VerifiedAt    *time.Time `json:"verifiedAt"`
	LastCheckedAt *time.Time `json:"lastCheckedAt"`
}

type dbOwnerDomain struct {
	Owner         models.RecordID `json:"owner"`
	Domain        string          `json:"domain"`
	Method        string          `json:"method"`
	Token         string          `json:"token"`
	Verified      bool            `json:"verified"`
	VerifiedAt    *time.Time      `json:"verified_at"`
	LastCheckedAt *time.Time      `json:"last_checked_at"`
	FailedChecks  int             `json:"failed_checks"`
}

func (row dbOwnerDomain) toDomain() OwnerDomain {
	return OwnerDomain{
		Domain: row.Domain, Method: row.Method, Token: row.Token, Verified: row.Verified,
		VerifiedAt: row.VerifiedAt, LastCheckedAt: row.LastCheckedAt,
	}
}

// ListDomains returns the owner's domains, oldest first.
func (s *SurrealStore) ListDomains(ctx context.Context, handle string) ([]OwnerDomain, error) {
	owner, err := s.ownerRecord(ctx, handle)
	if err != nil {
		return nil, err
	}
	rows, err := queryRows[dbOwnerDomain](ctx, s.DB, "SELECT * FROM owner_domain WHERE owner = $owner ORDER BY created_at, domain",
		map[string]any{"owner": owner})
	if err != nil {
		return nil, fmt.Errorf("list domains: %w", err)
	}
	domains := make([]OwnerDomain, 0, len(rows))
	for _, row := range rows {
		domains = append(domains, row.toDomain())
	}
	return domains, nil
}

// VerifiedDomainNames returns the names of the owner's verified domains.
func (s *SurrealStore) VerifiedDomainNames(ctx context.Context, handle string) ([]string, error) {
	domains, err := s.ListDomains(ctx, handle)
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, domain := range domains {
		if domain.Verified {
			names = append(names, domain.Domain)
		}
	}
	return names, nil
}

func (s *SurrealStore) getDomainRow(ctx context.Context, owner models.RecordID, domain string) (*dbOwnerDomain, error) {
	return queryFirst[dbOwnerDomain](ctx, s.DB, "SELECT * FROM owner_domain WHERE owner = $owner AND domain = $domain",
		map[string]any{"owner": owner, "domain": domain})
}

// GetDomain returns one of the owner's domains; ErrNotFound when it is not one.
func (s *SurrealStore) GetDomain(ctx context.Context, handle string, domain string) (*OwnerDomain, error) {
	owner, err := s.ownerRecord(ctx, handle)
	if err != nil {
		return nil, err
	}
	row, err := s.getDomainRow(ctx, owner, domain)
	if err != nil {
		return nil, err
	}
	found := row.toDomain()
	return &found, nil
}

// AddDomain registers a domain the owner will prove control of.
func (s *SurrealStore) AddDomain(ctx context.Context, handle string, domain string, method string, token string) (*OwnerDomain, error) {
	owner, err := s.ownerRecord(ctx, handle)
	if err != nil {
		return nil, err
	}
	_, err = s.getDomainRow(ctx, owner, domain)
	if err == nil {
		return nil, ErrDomainExists
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	row, err := queryFirst[dbOwnerDomain](ctx, s.DB,
		"CREATE owner_domain SET owner = $owner, domain = $domain, method = $method, token = $proof_token",
		map[string]any{"owner": owner, "domain": domain, "method": method, "proof_token": token})
	if err != nil {
		return nil, fmt.Errorf("add domain: %w", err)
	}
	added := row.toDomain()
	return &added, nil
}

// domainHeldByOther reports whether an owner other than the given one holds the
// domain verified.
func (s *SurrealStore) domainHeldByOther(ctx context.Context, owner models.RecordID, domain string) (bool, error) {
	rows, err := queryRows[countRow](ctx, s.DB,
		"SELECT count() FROM owner_domain WHERE domain = $domain AND verified = true AND owner != $owner GROUP ALL",
		map[string]any{"domain": domain, "owner": owner})
	if err != nil {
		return false, err
	}
	return len(rows) > 0 && rows[0].Count > 0, nil
}

// DomainCheck is the outcome of re-checking a domain: the domain after it, and
// whether the check just revoked a verification.
type DomainCheck struct {
	Domain  OwnerDomain
	Revoked bool
}

// RecordDomainCheck stores the result of checking the proof. A pass verifies the
// domain, or ErrDomainTaken when another owner holds it. A failure of a verified
// domain counts; the domain loses its verification at revokeAfter failures in a
// row, so one outage does not revoke it.
func (s *SurrealStore) RecordDomainCheck(ctx context.Context, handle string, domain string, passed bool, revokeAfter int) (*DomainCheck, error) {
	owner, err := s.ownerRecord(ctx, handle)
	if err != nil {
		return nil, err
	}
	row, err := s.getDomainRow(ctx, owner, domain)
	if err != nil {
		return nil, err
	}
	if passed {
		return s.markDomainPassed(ctx, owner, row)
	}
	return s.markDomainFailed(ctx, owner, row, revokeAfter)
}

func (s *SurrealStore) markDomainPassed(ctx context.Context, owner models.RecordID, row *dbOwnerDomain) (*DomainCheck, error) {
	heldByOther, err := s.domainHeldByOther(ctx, owner, row.Domain)
	if err != nil {
		return nil, err
	}
	if heldByOther {
		return nil, ErrDomainTaken
	}
	statement := "UPDATE owner_domain SET verified = true, failed_checks = 0, last_checked_at = time::now()"
	if !row.Verified {
		statement += ", verified_at = time::now()"
	}
	return s.updateDomain(ctx, owner, row.Domain, statement, false)
}

func (s *SurrealStore) markDomainFailed(ctx context.Context, owner models.RecordID, row *dbOwnerDomain, revokeAfter int) (*DomainCheck, error) {
	failed := row.FailedChecks + 1
	if row.Verified && failed >= revokeAfter {
		statement := "UPDATE owner_domain SET verified = false, verified_at = NONE, failed_checks = 0, last_checked_at = time::now()"
		return s.updateDomain(ctx, owner, row.Domain, statement, true)
	}
	statement := fmt.Sprintf("UPDATE owner_domain SET failed_checks = %d, last_checked_at = time::now()", failed)
	return s.updateDomain(ctx, owner, row.Domain, statement, false)
}

func (s *SurrealStore) updateDomain(ctx context.Context, owner models.RecordID, domain string, setClause string, revoked bool) (*DomainCheck, error) {
	row, err := queryFirst[dbOwnerDomain](ctx, s.DB, setClause+" WHERE owner = $owner AND domain = $domain",
		map[string]any{"owner": owner, "domain": domain})
	if err != nil {
		return nil, fmt.Errorf("update domain: %w", err)
	}
	return &DomainCheck{Domain: row.toDomain(), Revoked: revoked}, nil
}

// RemoveDomain deletes one of the owner's domains and reports whether it was
// verified, so the caller can refresh the owner's apps.
func (s *SurrealStore) RemoveDomain(ctx context.Context, handle string, domain string) (bool, error) {
	owner, err := s.ownerRecord(ctx, handle)
	if err != nil {
		return false, err
	}
	row, err := s.getDomainRow(ctx, owner, domain)
	if err != nil {
		return false, err
	}
	err = queryExec(ctx, s.DB, "DELETE owner_domain WHERE owner = $owner AND domain = $domain",
		map[string]any{"owner": owner, "domain": domain})
	if err != nil {
		return false, fmt.Errorf("remove domain: %w", err)
	}
	return row.Verified, nil
}

// VerifiedDomain is a verified domain with the handle of its owner.
type VerifiedDomain struct {
	OwnerHandle string
	Domain      string
	Method      string
	Token       string
}

type dbVerifiedDomain struct {
	Owner      models.RecordID `json:"owner"`
	OwnerLogin *string         `json:"owner_handle"`
	Domain     string          `json:"domain"`
	Method     string          `json:"method"`
	Token      string          `json:"token"`
}

// ListVerifiedDomainsCheckedBefore returns the verified domains last checked
// before the cutoff, oldest check first, at most limit of them.
func (s *SurrealStore) ListVerifiedDomainsCheckedBefore(ctx context.Context, cutoff time.Time, limit int) ([]VerifiedDomain, error) {
	rows, err := queryRows[dbVerifiedDomain](ctx, s.DB,
		`SELECT owner, owner.handle AS owner_handle, domain, method, token, last_checked_at FROM owner_domain
		WHERE verified = true AND (last_checked_at = NONE OR last_checked_at < <datetime>$cutoff)
		ORDER BY last_checked_at LIMIT $limit`,
		map[string]any{"cutoff": cutoff.UTC().Format(time.RFC3339Nano), "limit": limit})
	if err != nil {
		return nil, fmt.Errorf("list domains to re-check: %w", err)
	}
	domains := make([]VerifiedDomain, 0, len(rows))
	for _, row := range rows {
		domains = append(domains, VerifiedDomain{OwnerHandle: row.handle(), Domain: row.Domain, Method: row.Method, Token: row.Token})
	}
	return domains, nil
}

func (row dbVerifiedDomain) handle() string {
	if row.Owner.Table == "organization" {
		return recordTail(row.Owner)
	}
	if row.OwnerLogin == nil {
		return ""
	}
	return *row.OwnerLogin
}
