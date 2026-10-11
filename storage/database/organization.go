package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/neoworks/auth/ownership"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

var (
	// ErrAlreadyMember means the user already belongs to the organization.
	ErrAlreadyMember = errors.New("already a member")
	// ErrOwnsApps means the organization still owns apps and cannot be archived.
	ErrOwnsApps = errors.New("organization owns apps")
	// ErrArchived means the organization is archived and accepts no changes.
	ErrArchived = errors.New("organization archived")
)

// Organization is an organization as its members see it.
type Organization struct {
	Owner
	CreatedAt  time.Time         `json:"createdAt"`
	ArchivedAt *time.Time        `json:"archivedAt"`
	MyGrants   []ownership.Grant `json:"myGrants"`
}

// Member is one member of an organization with the grants they hold.
type Member struct {
	UserID      string            `json:"userId"`
	Handle      *string           `json:"handle"`
	DisplayName string            `json:"displayName"`
	Email       string            `json:"email"`
	JoinedAt    time.Time         `json:"joinedAt"`
	Grants      []ownership.Grant `json:"grants"`
}

type dbMemberGrant struct {
	Permission string  `json:"permission"`
	App        *string `json:"app"`
}

type dbOrganization struct {
	ID          models.RecordID `json:"id"`
	DisplayName string          `json:"display_name"`
	ArchivedAt  *time.Time      `json:"archived_at"`
	VerifiedAt  *time.Time      `json:"verified_at"`
	CreatedAt   time.Time       `json:"created_at"`
}

type dbMember struct {
	User      models.RecordID `json:"user"`
	Handle    *string         `json:"handle"`
	FirstName *string         `json:"first_name"`
	LastName  *string         `json:"last_name"`
	Email     string          `json:"email"`
	Grants    []dbMemberGrant `json:"grants"`
	JoinedAt  time.Time       `json:"joined_at"`
}

type dbMembership struct {
	Organization models.RecordID `json:"organization"`
	DisplayName  string          `json:"display_name"`
	Verified     bool            `json:"verified"`
	Grants       []dbMemberGrant `json:"grants"`
}

func organizationRecord(handle string) models.RecordID {
	return models.NewRecordID("organization", handle)
}

func memberGrantsFromRows(rows []dbMemberGrant) []ownership.Grant {
	grants := make([]ownership.Grant, 0, len(rows))
	for _, row := range rows {
		grants = append(grants, ownership.Grant{Permission: ownership.Permission(row.Permission), AppID: row.App})
	}
	return grants
}

// memberGrantRows shapes grants for storage, leaving `app` out of organization-wide
// grants so the optional field stays NONE.
func memberGrantRows(grants []ownership.Grant) []map[string]any {
	rows := make([]map[string]any, 0, len(grants))
	for _, grant := range grants {
		row := map[string]any{"permission": string(grant.Permission)}
		if grant.AppID != nil {
			row["app"] = *grant.AppID
		}
		rows = append(rows, row)
	}
	return rows
}

func recordTail(record models.RecordID) string {
	tail, _ := record.ID.(string)
	return tail
}

func (row dbOrganization) toOrganization(grants []ownership.Grant) *Organization {
	handle := recordTail(row.ID)
	return &Organization{
		Owner:      Owner{Handle: handle, Kind: OwnerKindOrganization, DisplayName: row.DisplayName, Verified: row.VerifiedAt != nil},
		CreatedAt:  row.CreatedAt,
		ArchivedAt: row.ArchivedAt,
		MyGrants:   grants,
	}
}

func (row dbMember) toMember() Member {
	name := dbUserName{Handle: row.Handle, FirstName: row.FirstName, LastName: row.LastName}
	return Member{
		UserID: recordTail(row.User), Handle: row.Handle, DisplayName: userDisplayName(name),
		Email: row.Email, JoinedAt: row.JoinedAt, Grants: memberGrantsFromRows(row.Grants),
	}
}

const createOrganizationStatement = `
	BEGIN TRANSACTION;
	CREATE $handle_ref SET kind = 'organization', organization = $organization;
	CREATE $organization SET display_name = $display_name, created_by = $user;
	CREATE organization_member SET organization = $organization, user = $user, grants = $grants;
	COMMIT TRANSACTION;`

func createOrganizationParams(userID string, handle string, displayName string) map[string]any {
	return map[string]any{
		"handle_ref": handleRecord(handle), "organization": organizationRecord(handle),
		"display_name": displayName, "user": userRecord(userID), "grants": memberGrantRows(ownership.AllGrants()),
	}
}

// CreateOrganization claims the handle for a new organization whose creator
// holds every permission. The creator needs a handle of their own.
func (s *SurrealStore) CreateOrganization(ctx context.Context, userID string, handle string, displayName string) (*Organization, error) {
	if _, err := s.UserOwner(ctx, userID); err != nil {
		return nil, err
	}
	taken, err := s.IsHandleTaken(ctx, handle)
	if err != nil {
		return nil, err
	}
	if taken {
		return nil, ErrHandleTaken
	}
	if err := queryExec(ctx, s.DB, createOrganizationStatement, createOrganizationParams(userID, handle, displayName)); err != nil {
		return nil, s.explainOrganizationFailure(ctx, handle, err)
	}
	return s.GetOrganization(ctx, handle, userID)
}

func (s *SurrealStore) explainOrganizationFailure(ctx context.Context, handle string, createErr error) error {
	taken, err := s.IsHandleTaken(ctx, handle)
	if err == nil && taken {
		return ErrHandleTaken
	}
	return fmt.Errorf("create organization: %w", createErr)
}

func (s *SurrealStore) getOrganizationRow(ctx context.Context, handle string) (*dbOrganization, error) {
	return queryFirst[dbOrganization](ctx, s.DB, "SELECT * FROM $organization",
		map[string]any{"organization": organizationRecord(handle)})
}

// GetOrganization returns the organization with the grants userID holds in it;
// ErrForbidden when they are not a member.
func (s *SurrealStore) GetOrganization(ctx context.Context, handle string, userID string) (*Organization, error) {
	grants, err := s.memberGrants(ctx, handle, userID)
	if err != nil {
		return nil, err
	}
	row, err := s.getOrganizationRow(ctx, handle)
	if err != nil {
		return nil, err
	}
	return row.toOrganization(grants), nil
}

func (s *SurrealStore) organizationOwner(ctx context.Context, handle string) (*Owner, error) {
	row, err := s.getOrganizationRow(ctx, handle)
	if err != nil {
		return nil, err
	}
	return &row.toOrganization(nil).Owner, nil
}

// RenameOrganization changes the display name; the handle never changes.
func (s *SurrealStore) RenameOrganization(ctx context.Context, handle string, displayName string) error {
	return queryExec(ctx, s.DB, "UPDATE $organization SET display_name = $display_name WHERE archived_at = NONE",
		map[string]any{"organization": organizationRecord(handle), "display_name": displayName})
}

// ArchiveOrganization stops all changes to an organization that owns no apps.
// Its handle stays taken and its published schemas stay readable.
func (s *SurrealStore) ArchiveOrganization(ctx context.Context, handle string) error {
	apps, err := s.countOwnedApps(ctx, handle)
	if err != nil {
		return err
	}
	if apps > 0 {
		return ErrOwnsApps
	}
	return queryExec(ctx, s.DB, "UPDATE $organization SET archived_at = time::now() WHERE archived_at = NONE",
		map[string]any{"organization": organizationRecord(handle)})
}

type countRow struct {
	Count int `json:"count"`
}

// countOwnedApps counts the OAuth clients the organization owns.
func (s *SurrealStore) countOwnedApps(ctx context.Context, handle string) (int, error) {
	rows, err := queryRows[countRow](ctx, s.DB, "SELECT count() FROM client WHERE owner = $owner GROUP ALL",
		map[string]any{"owner": organizationRecord(handle)})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[0].Count, nil
}

// IsArchived reports whether the organization is archived.
func (s *SurrealStore) IsArchived(ctx context.Context, handle string) (bool, error) {
	row, err := s.getOrganizationRow(ctx, handle)
	if err != nil {
		return false, err
	}
	return row.ArchivedAt != nil, nil
}

const memberSelection = `SELECT user, user.handle AS handle, user.first_name AS first_name,
	user.last_name AS last_name, user.email AS email, grants, joined_at FROM organization_member`

// ListMembers returns every member, earliest first.
func (s *SurrealStore) ListMembers(ctx context.Context, handle string) ([]Member, error) {
	rows, err := queryRows[dbMember](ctx, s.DB, memberSelection+" WHERE organization = $organization ORDER BY joined_at",
		map[string]any{"organization": organizationRecord(handle)})
	if err != nil {
		return nil, err
	}
	members := make([]Member, 0, len(rows))
	for _, row := range rows {
		members = append(members, row.toMember())
	}
	return members, nil
}

// GetMember returns one member; ErrNotFound when the user is not a member.
func (s *SurrealStore) GetMember(ctx context.Context, handle string, userID string) (*Member, error) {
	row, err := queryFirst[dbMember](ctx, s.DB, memberSelection+" WHERE organization = $organization AND user = $user",
		map[string]any{"organization": organizationRecord(handle), "user": userRecord(userID)})
	if err != nil {
		return nil, err
	}
	member := row.toMember()
	return &member, nil
}

// MemberGrantsByUser maps every member's user id to their grants, for the rules
// that look at the whole organization.
func (s *SurrealStore) MemberGrantsByUser(ctx context.Context, handle string) (map[string][]ownership.Grant, error) {
	members, err := s.ListMembers(ctx, handle)
	if err != nil {
		return nil, err
	}
	byUser := make(map[string][]ownership.Grant, len(members))
	for _, member := range members {
		byUser[member.UserID] = member.Grants
	}
	return byUser, nil
}

// memberGrants returns the user's grants in the organization; ErrForbidden when
// they are not a member.
func (s *SurrealStore) memberGrants(ctx context.Context, handle string, userID string) ([]ownership.Grant, error) {
	member, err := s.GetMember(ctx, handle, userID)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrForbidden
	}
	if err != nil {
		return nil, err
	}
	return member.Grants, nil
}

// SetMemberGrants replaces a member's grants; the caller applied the rules.
func (s *SurrealStore) SetMemberGrants(ctx context.Context, handle string, userID string, grants []ownership.Grant) error {
	return queryExec(ctx, s.DB, "UPDATE organization_member SET grants = $grants WHERE organization = $organization AND user = $user",
		map[string]any{"organization": organizationRecord(handle), "user": userRecord(userID), "grants": memberGrantRows(grants)})
}

// RemoveMember ends a membership; the caller applied the rules.
func (s *SurrealStore) RemoveMember(ctx context.Context, handle string, userID string) error {
	return queryExec(ctx, s.DB, "DELETE organization_member WHERE organization = $organization AND user = $user",
		map[string]any{"organization": organizationRecord(handle), "user": userRecord(userID)})
}

// AddMember makes the user a member with the grants.
func (s *SurrealStore) AddMember(ctx context.Context, handle string, userID string, grants []ownership.Grant) error {
	_, err := s.GetMember(ctx, handle, userID)
	if err == nil {
		return ErrAlreadyMember
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	return queryExec(ctx, s.DB, "CREATE organization_member SET organization = $organization, user = $user, grants = $grants",
		map[string]any{"organization": organizationRecord(handle), "user": userRecord(userID), "grants": memberGrantRows(grants)})
}

func (s *SurrealStore) organizationMembershipsOf(ctx context.Context, userID string) ([]OwnerMembership, error) {
	rows, err := queryRows[dbMembership](ctx, s.DB,
		`SELECT organization, organization.display_name AS display_name,
			organization.verified_at != NONE AS verified, grants FROM organization_member
		WHERE user = $user AND organization.archived_at = NONE ORDER BY display_name`,
		map[string]any{"user": userRecord(userID)})
	if err != nil {
		return nil, err
	}
	memberships := make([]OwnerMembership, 0, len(rows))
	for _, row := range rows {
		owner := Owner{Handle: recordTail(row.Organization), Kind: OwnerKindOrganization, DisplayName: row.DisplayName, Verified: row.Verified}
		memberships = append(memberships, OwnerMembership{Owner: owner, Grants: memberGrantsFromRows(row.Grants)})
	}
	return memberships, nil
}
