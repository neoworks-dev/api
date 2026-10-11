package database

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/neoworks/auth/ownership"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

var (
	// ErrHandleTaken means another person or organization holds the handle, now
	// or in the past; handles are never released.
	ErrHandleTaken = errors.New("handle taken")
	// ErrHandleAlreadySet means the user already picked their handle; it never changes.
	ErrHandleAlreadySet = errors.New("handle already set")
	// ErrHandleRequired means the user must pick a handle before this action.
	ErrHandleRequired = errors.New("handle required")
)

const (
	OwnerKindUser         = "user"
	OwnerKindOrganization = "organization"
)

// Owner is a person or an organization as other users see it.
type Owner struct {
	Handle      string `json:"handle"`
	Kind        string `json:"kind"`
	DisplayName string `json:"displayName"`
	Verified    bool   `json:"verified"`
}

// OwnerMembership is an owner the user may act for, with the grants they hold.
type OwnerMembership struct {
	Owner  Owner             `json:"owner"`
	Grants []ownership.Grant `json:"grants"`
}

type dbHandle struct {
	Kind         string           `json:"kind"`
	User         *models.RecordID `json:"user"`
	Organization *models.RecordID `json:"organization"`
}

type dbUserName struct {
	ID        models.RecordID `json:"id"`
	Handle    *string         `json:"handle"`
	FirstName *string         `json:"first_name"`
	LastName  *string         `json:"last_name"`
}

func handleRecord(handle string) models.RecordID {
	return models.NewRecordID("handle", handle)
}

func userRecord(userID string) models.RecordID {
	return models.NewRecordID("user", userID)
}

// userDisplayName is the user's name, or their handle when they gave none.
func userDisplayName(row dbUserName) string {
	parts := []string{}
	if row.FirstName != nil && *row.FirstName != "" {
		parts = append(parts, *row.FirstName)
	}
	if row.LastName != nil && *row.LastName != "" {
		parts = append(parts, *row.LastName)
	}
	if len(parts) > 0 {
		return strings.Join(parts, " ")
	}
	if row.Handle != nil {
		return *row.Handle
	}
	return ""
}

// GetUserHandle returns the user's handle, or "" when they have not picked one.
func (s *SurrealStore) GetUserHandle(ctx context.Context, userID string) (string, error) {
	row, err := s.getUserName(ctx, userID)
	if err != nil {
		return "", err
	}
	if row.Handle == nil {
		return "", nil
	}
	return *row.Handle, nil
}

func (s *SurrealStore) getUserName(ctx context.Context, userID string) (*dbUserName, error) {
	return queryFirst[dbUserName](ctx, s.DB,
		"SELECT id, handle, first_name, last_name FROM $user",
		map[string]any{"user": userRecord(userID)})
}

// IsHandleTaken reports whether a person or organization holds the handle.
func (s *SurrealStore) IsHandleTaken(ctx context.Context, handle string) (bool, error) {
	_, err := s.getHandle(ctx, handle)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *SurrealStore) getHandle(ctx context.Context, handle string) (*dbHandle, error) {
	return queryFirst[dbHandle](ctx, s.DB, "SELECT * FROM $handle", map[string]any{"handle": handleRecord(handle)})
}

const claimUserHandleStatement = `
	BEGIN TRANSACTION;
	CREATE $handle_ref SET kind = 'user', user = $user;
	UPDATE $user SET handle = $handle WHERE handle = NONE;
	COMMIT TRANSACTION;`

func claimUserHandleParams(userID string, handle string) map[string]any {
	return map[string]any{"handle_ref": handleRecord(handle), "handle": handle, "user": userRecord(userID)}
}

// ClaimUserHandle gives the user a handle. It fails when they already have one
// or the handle is held; the caller checks the handle's form first.
func (s *SurrealStore) ClaimUserHandle(ctx context.Context, userID string, handle string) error {
	current, err := s.GetUserHandle(ctx, userID)
	if err != nil {
		return err
	}
	if current != "" {
		return ErrHandleAlreadySet
	}
	taken, err := s.IsHandleTaken(ctx, handle)
	if err != nil {
		return err
	}
	if taken {
		return ErrHandleTaken
	}
	if err := queryExec(ctx, s.DB, claimUserHandleStatement, claimUserHandleParams(userID, handle)); err != nil {
		return s.explainClaimFailure(ctx, userID, handle, err)
	}
	return nil
}

// explainClaimFailure reports why a claim that passed the checks failed: a
// concurrent claim of the same handle or by the same user.
func (s *SurrealStore) explainClaimFailure(ctx context.Context, userID string, handle string, claimErr error) error {
	current, err := s.GetUserHandle(ctx, userID)
	if err == nil && current != "" && current != handle {
		return ErrHandleAlreadySet
	}
	taken, err := s.IsHandleTaken(ctx, handle)
	if err == nil && taken {
		return ErrHandleTaken
	}
	return fmt.Errorf("claim handle: %w", claimErr)
}

// GetOwner resolves a handle to the person or organization holding it.
func (s *SurrealStore) GetOwner(ctx context.Context, handle string) (*Owner, error) {
	row, err := s.getHandle(ctx, handle)
	if err != nil {
		return nil, err
	}
	if row.Kind == OwnerKindOrganization {
		return s.organizationOwner(ctx, handle)
	}
	userID, _ := row.User.ID.(string)
	name, err := s.getUserName(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &Owner{Handle: handle, Kind: OwnerKindUser, DisplayName: userDisplayName(*name)}, nil
}

// HandleUserID returns the user holding a personal handle, or ErrNotFound when
// the handle is free or held by an organization.
func (s *SurrealStore) HandleUserID(ctx context.Context, handle string) (string, error) {
	row, err := s.getHandle(ctx, handle)
	if err != nil {
		return "", err
	}
	if row.Kind != OwnerKindUser || row.User == nil {
		return "", ErrNotFound
	}
	userID, _ := row.User.ID.(string)
	return userID, nil
}

// UserOwner is how the user appears as an owner; ErrHandleRequired when they
// have no handle yet.
func (s *SurrealStore) UserOwner(ctx context.Context, userID string) (*Owner, error) {
	name, err := s.getUserName(ctx, userID)
	if err != nil {
		return nil, err
	}
	if name.Handle == nil {
		return nil, ErrHandleRequired
	}
	return &Owner{Handle: *name.Handle, Kind: OwnerKindUser, DisplayName: userDisplayName(*name)}, nil
}

// OwnersOf lists the owners the user may act for: themselves when they have a
// handle, with every permission, then their organizations.
func (s *SurrealStore) OwnersOf(ctx context.Context, userID string) ([]OwnerMembership, error) {
	memberships := []OwnerMembership{}
	personal, err := s.UserOwner(ctx, userID)
	if err == nil {
		memberships = append(memberships, OwnerMembership{Owner: *personal, Grants: ownership.AllGrants()})
	}
	if err != nil && !errors.Is(err, ErrHandleRequired) {
		return nil, err
	}
	organizations, err := s.organizationMembershipsOf(ctx, userID)
	if err != nil {
		return nil, err
	}
	return append(memberships, organizations...), nil
}

// GrantsFor returns what the user may do for the owner: everything for their own
// handle, their member grants for an organization, and ErrForbidden otherwise.
func (s *SurrealStore) GrantsFor(ctx context.Context, userID string, handle string) ([]ownership.Grant, error) {
	row, err := s.getHandle(ctx, handle)
	if err != nil {
		return nil, err
	}
	if row.Kind == OwnerKindOrganization {
		return s.memberGrants(ctx, handle, userID)
	}
	holder, _ := row.User.ID.(string)
	if holder != userID {
		return nil, ErrForbidden
	}
	return ownership.AllGrants(), nil
}
