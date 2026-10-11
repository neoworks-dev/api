package database

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/neoworks/auth/ownership"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// InvitationLifetime is how long an invitation can be accepted.
const InvitationLifetime = 14 * 24 * time.Hour

// Invitation is an offer of membership as the organization sees it. Exactly one
// of Email and ContactCode is set.
type Invitation struct {
	ID          string            `json:"id"`
	Email       *string           `json:"email,omitempty"`
	ContactCode *string           `json:"contactCode,omitempty"`
	Grants      []ownership.Grant `json:"grants"`
	InvitedBy   Owner             `json:"invitedBy"`
	CreatedAt   time.Time         `json:"createdAt"`
	ExpiresAt   time.Time         `json:"expiresAt"`
}

// ReceivedInvitation is an invitation as its invitee sees it.
type ReceivedInvitation struct {
	ID           string            `json:"id"`
	Organization Owner             `json:"organization"`
	Grants       []ownership.Grant `json:"grants"`
	InvitedBy    Owner             `json:"invitedBy"`
	ExpiresAt    time.Time         `json:"expiresAt"`
}

// InvitationInput addresses an invitation by email or by contact code.
type InvitationInput struct {
	Email       string
	ContactCode string
	Grants      []ownership.Grant
}

type dbInvitation struct {
	ID               models.RecordID `json:"id"`
	Organization     models.RecordID `json:"organization"`
	OrganizationName string          `json:"organization_name"`
	Email            *string         `json:"email"`
	ContactCode      *string         `json:"contact_code"`
	Grants           []dbMemberGrant `json:"grants"`
	InviterHandle    *string         `json:"inviter_handle"`
	InviterFirst     *string         `json:"inviter_first_name"`
	InviterLast      *string         `json:"inviter_last_name"`
	CreatedAt        time.Time       `json:"created_at"`
	ExpiresAt        time.Time       `json:"expires_at"`
}

func invitationRecord(invitationID string) models.RecordID {
	return models.NewRecordID("organization_invitation", invitationID)
}

func (row dbInvitation) inviter() Owner {
	name := dbUserName{Handle: row.InviterHandle, FirstName: row.InviterFirst, LastName: row.InviterLast}
	owner := Owner{Kind: OwnerKindUser, DisplayName: userDisplayName(name)}
	if row.InviterHandle != nil {
		owner.Handle = *row.InviterHandle
	}
	return owner
}

func (row dbInvitation) toInvitation() Invitation {
	return Invitation{
		ID: recordTail(row.ID), Email: row.Email, ContactCode: row.ContactCode, Grants: memberGrantsFromRows(row.Grants),
		InvitedBy: row.inviter(), CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt,
	}
}

func (row dbInvitation) toReceived() ReceivedInvitation {
	organization := Owner{Handle: recordTail(row.Organization), Kind: OwnerKindOrganization, DisplayName: row.OrganizationName}
	return ReceivedInvitation{
		ID: recordTail(row.ID), Organization: organization, Grants: memberGrantsFromRows(row.Grants),
		InvitedBy: row.inviter(), ExpiresAt: row.ExpiresAt,
	}
}

const invitationSelection = `SELECT id, organization, organization.display_name AS organization_name, email,
	contact_code, grants, invited_by.handle AS inviter_handle, invited_by.first_name AS inviter_first_name,
	invited_by.last_name AS inviter_last_name, created_at, expires_at FROM organization_invitation`

// invitationStatement creates an invitation, setting only the address it uses.
func invitationStatement(input InvitationInput) string {
	assignments := "organization = $organization, grants = $grants, invited_by = $invited_by, expires_at = $expires_at"
	if input.ContactCode != "" {
		return "CREATE $invitation SET " + assignments + ", contact_code = $contact_code, invitee = $invitee"
	}
	return "CREATE $invitation SET " + assignments + ", email = $email"
}

func invitationParams(handle string, inviterID string, input InvitationInput, inviteeID string, invitationID string) map[string]any {
	params := map[string]any{
		"invitation": invitationRecord(invitationID), "organization": organizationRecord(handle),
		"grants": memberGrantRows(input.Grants), "invited_by": userRecord(inviterID),
		"expires_at": time.Now().Add(InvitationLifetime),
	}
	if input.ContactCode != "" {
		params["contact_code"] = input.ContactCode
		params["invitee"] = userRecord(inviteeID)
		return params
	}
	params["email"] = strings.ToLower(input.Email)
	return params
}

// CreateInvitation stores an invitation; a contact code must resolve to a user.
func (s *SurrealStore) CreateInvitation(ctx context.Context, handle string, inviterID string, input InvitationInput) (*Invitation, error) {
	inviteeID, err := s.inviteeOf(ctx, input)
	if err != nil {
		return nil, err
	}
	invitationID := uuid.NewString()
	params := invitationParams(handle, inviterID, input, inviteeID, invitationID)
	if err := queryExec(ctx, s.DB, invitationStatement(input), params); err != nil {
		return nil, err
	}
	row, err := queryFirst[dbInvitation](ctx, s.DB, invitationSelection+" WHERE id = $invitation",
		map[string]any{"invitation": invitationRecord(invitationID)})
	if err != nil {
		return nil, err
	}
	invitation := row.toInvitation()
	return &invitation, nil
}

func (s *SurrealStore) inviteeOf(ctx context.Context, input InvitationInput) (string, error) {
	if input.ContactCode == "" {
		return "", nil
	}
	identity, err := s.ResolveContactCode(ctx, input.ContactCode)
	if errors.Is(err, ErrNotFound) {
		return "", ErrUnknownPrincipal
	}
	if err != nil {
		return "", err
	}
	return identity.UserID, nil
}

// ListInvitations returns the organization's open invitations, newest first.
func (s *SurrealStore) ListInvitations(ctx context.Context, handle string) ([]Invitation, error) {
	rows, err := queryRows[dbInvitation](ctx, s.DB,
		invitationSelection+" WHERE organization = $organization AND expires_at > time::now() ORDER BY created_at DESC",
		map[string]any{"organization": organizationRecord(handle)})
	if err != nil {
		return nil, err
	}
	invitations := make([]Invitation, 0, len(rows))
	for _, row := range rows {
		invitations = append(invitations, row.toInvitation())
	}
	return invitations, nil
}

// RevokeInvitation deletes one of the organization's invitations.
func (s *SurrealStore) RevokeInvitation(ctx context.Context, handle string, invitationID string) error {
	if _, err := s.organizationInvitation(ctx, handle, invitationID); err != nil {
		return err
	}
	return queryExec(ctx, s.DB, "DELETE $invitation", map[string]any{"invitation": invitationRecord(invitationID)})
}

func (s *SurrealStore) organizationInvitation(ctx context.Context, handle string, invitationID string) (*dbInvitation, error) {
	return queryFirst[dbInvitation](ctx, s.DB, invitationSelection+" WHERE id = $invitation AND organization = $organization",
		map[string]any{"invitation": invitationRecord(invitationID), "organization": organizationRecord(handle)})
}

const receivedInvitationCondition = ` WHERE (invitee = $user OR email = $email) AND expires_at > time::now()
	AND organization.archived_at = NONE`

// ListReceivedInvitations returns the open invitations addressed to the user,
// by contact code or by their account email.
func (s *SurrealStore) ListReceivedInvitations(ctx context.Context, userID string) ([]ReceivedInvitation, error) {
	params, err := s.receivedInvitationParams(ctx, userID)
	if err != nil {
		return nil, err
	}
	rows, err := queryRows[dbInvitation](ctx, s.DB, invitationSelection+receivedInvitationCondition+" ORDER BY created_at DESC", params)
	if err != nil {
		return nil, err
	}
	invitations := make([]ReceivedInvitation, 0, len(rows))
	for _, row := range rows {
		invitations = append(invitations, row.toReceived())
	}
	return invitations, nil
}

func (s *SurrealStore) receivedInvitationParams(ctx context.Context, userID string) (map[string]any, error) {
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"user": userRecord(userID), "email": strings.ToLower(user.Email)}, nil
}

// ReceivedInvitation returns an open invitation addressed to the user;
// ErrNotFound for anyone else's.
func (s *SurrealStore) ReceivedInvitation(ctx context.Context, userID string, invitationID string) (*ReceivedInvitation, error) {
	params, err := s.receivedInvitationParams(ctx, userID)
	if err != nil {
		return nil, err
	}
	params["invitation"] = invitationRecord(invitationID)
	row, err := queryFirst[dbInvitation](ctx, s.DB, invitationSelection+receivedInvitationCondition+" AND id = $invitation", params)
	if err != nil {
		return nil, err
	}
	invitation := row.toReceived()
	return &invitation, nil
}

// AcceptInvitation makes the user a member with the invitation's grants and
// deletes it.
func (s *SurrealStore) AcceptInvitation(ctx context.Context, userID string, invitationID string) (*ReceivedInvitation, error) {
	invitation, err := s.ReceivedInvitation(ctx, userID, invitationID)
	if err != nil {
		return nil, err
	}
	if err := s.AddMember(ctx, invitation.Organization.Handle, userID, invitation.Grants); err != nil {
		return nil, err
	}
	if err := s.deleteInvitation(ctx, invitationID); err != nil {
		return nil, err
	}
	return invitation, nil
}

// DeclineInvitation deletes an invitation addressed to the user.
func (s *SurrealStore) DeclineInvitation(ctx context.Context, userID string, invitationID string) (*ReceivedInvitation, error) {
	invitation, err := s.ReceivedInvitation(ctx, userID, invitationID)
	if err != nil {
		return nil, err
	}
	return invitation, s.deleteInvitation(ctx, invitationID)
}

func (s *SurrealStore) deleteInvitation(ctx context.Context, invitationID string) error {
	return queryExec(ctx, s.DB, "DELETE $invitation", map[string]any{"invitation": invitationRecord(invitationID)})
}
