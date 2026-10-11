package database

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/neoworks/auth/ownership"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// IsPlatformAdmin reports whether the user is a member of the Neoworks
// organization holding platform.admin.
func (s *SurrealStore) IsPlatformAdmin(ctx context.Context, userID string) (bool, error) {
	grants, err := s.memberGrants(ctx, ownership.PlatformOrganization, userID)
	if errors.Is(err, ErrForbidden) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return ownership.Allows(grants, ownership.PlatformAdmin, ""), nil
}

type dbEmailUser struct {
	ID models.RecordID `json:"id"`
}

// EnsurePlatformAdmins makes the accounts with these emails members of the
// Neoworks organization holding every permission and platform.admin. Emails
// without an account are skipped; it is the bootstrap of the administrators.
func (s *SurrealStore) EnsurePlatformAdmins(ctx context.Context, emails []string) error {
	for _, email := range emails {
		email = strings.ToLower(strings.TrimSpace(email))
		if email == "" {
			continue
		}
		if err := s.ensurePlatformAdmin(ctx, email); err != nil {
			return err
		}
	}
	return nil
}

func (s *SurrealStore) ensurePlatformAdmin(ctx context.Context, email string) error {
	row, err := queryFirst[dbEmailUser](ctx, s.DB, "SELECT id FROM user WHERE string::lowercase(email) = $email",
		map[string]any{"email": email})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("find platform admin: %w", err)
	}
	userID := recordTail(row.ID)
	grants := append(ownership.AllGrants(), ownership.OrganizationWide(ownership.PlatformAdmin))
	err = s.AddMember(ctx, ownership.PlatformOrganization, userID, grants)
	if errors.Is(err, ErrAlreadyMember) {
		return s.SetMemberGrants(ctx, ownership.PlatformOrganization, userID, ownership.Normalize(grants))
	}
	return err
}

// SetOrganizationVerified marks an organization as reviewed and verified by
// Neoworks, or clears the mark. It reports whether the mark changed.
func (s *SurrealStore) SetOrganizationVerified(ctx context.Context, handle string, verified bool) (bool, error) {
	row, err := s.getOrganizationRow(ctx, handle)
	if err != nil {
		return false, err
	}
	if (row.VerifiedAt != nil) == verified {
		return false, nil
	}
	statement := "UPDATE $organization SET verified_at = NONE"
	if verified {
		statement = "UPDATE $organization SET verified_at = time::now()"
	}
	err = queryExec(ctx, s.DB, statement, map[string]any{"organization": organizationRecord(handle)})
	if err != nil {
		return false, fmt.Errorf("set organization verified: %w", err)
	}
	return true, nil
}

// SetRateLimitMultiplier sets the multiplier an operator chose for the client's
// rate limits; nil returns the client to the multiplier its standing derives.
func (s *SurrealStore) SetRateLimitMultiplier(ctx context.Context, clientID string, multiplier *float64) error {
	if _, err := s.GetApp(ctx, clientID); err != nil {
		return err
	}
	statement := "UPDATE $client SET rate_limit_multiplier = NONE"
	params := map[string]any{"client": clientRecord(clientID)}
	if multiplier != nil {
		statement = "UPDATE $client SET rate_limit_multiplier = $multiplier"
		params["multiplier"] = *multiplier
	}
	return queryExec(ctx, s.DB, statement, params)
}
