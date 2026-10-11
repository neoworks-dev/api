package database

import (
	"context"
	"time"

	"github.com/surrealdb/surrealdb.go/pkg/models"
)

const (
	defaultAuditLimit = 50
	maxAuditLimit     = 200
)

// Audit actions recorded for an organization.
const (
	AuditOrganizationCreated  = "organization.created"
	AuditOrganizationRenamed  = "organization.renamed"
	AuditOrganizationArchived = "organization.archived"
	AuditMemberGrantsChanged  = "member.grants_changed"
	AuditMemberRemoved        = "member.removed"
	AuditMemberLeft           = "member.left"
	AuditInvitationCreated    = "invitation.created"
	AuditInvitationRevoked    = "invitation.revoked"
	AuditInvitationAccepted   = "invitation.accepted"
	AuditInvitationDeclined   = "invitation.declined"

	AuditAppCreated             = "app.created"
	AuditAppDeleted             = "app.deleted"
	AuditAppRedirectURIsChanged = "app.redirect_uris_changed"
	AuditAppScopesChanged       = "app.scopes_changed"
	AuditAppSecretRotated       = "app.secret_rotated"
)

// AuditTarget is what an audit entry is about.
type AuditTarget struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Label string `json:"label"`
}

// AuditInput is one action to record.
type AuditInput struct {
	Organization string
	ActorID      string
	Action       string
	Target       AuditTarget
	Details      map[string]any
}

// AuditEntry is a recorded action as members with audit.view see it.
type AuditEntry struct {
	ID      string         `json:"id"`
	At      time.Time      `json:"at"`
	Actor   Owner          `json:"actor"`
	Action  string         `json:"action"`
	Target  AuditTarget    `json:"target"`
	Details map[string]any `json:"details"`
}

// AuditPage is a page of entries, newest first; NextCursor continues it.
type AuditPage struct {
	Entries    []AuditEntry `json:"entries"`
	NextCursor *string      `json:"nextCursor"`
}

type dbAuditEntry struct {
	ID          models.RecordID `json:"id"`
	At          time.Time       `json:"at"`
	ActorHandle *string         `json:"actor_handle"`
	ActorFirst  *string         `json:"actor_first_name"`
	ActorLast   *string         `json:"actor_last_name"`
	Action      string          `json:"action"`
	TargetKind  string          `json:"target_kind"`
	TargetID    string          `json:"target_id"`
	TargetLabel string          `json:"target_label"`
	Details     map[string]any  `json:"details"`
}

func (row dbAuditEntry) toEntry() AuditEntry {
	name := dbUserName{Handle: row.ActorHandle, FirstName: row.ActorFirst, LastName: row.ActorLast}
	actor := Owner{Kind: OwnerKindUser, DisplayName: userDisplayName(name)}
	if row.ActorHandle != nil {
		actor.Handle = *row.ActorHandle
	}
	details := row.Details
	if details == nil {
		details = map[string]any{}
	}
	return AuditEntry{
		ID: recordTail(row.ID), At: row.At, Actor: actor, Action: row.Action,
		Target: AuditTarget{Kind: row.TargetKind, ID: row.TargetID, Label: row.TargetLabel}, Details: details,
	}
}

const recordAuditStatement = `CREATE organization_audit SET organization = $organization, actor = $actor,
	action = $action, target_kind = $target_kind, target_id = $target_id, target_label = $target_label, details = $details`

func recordAuditParams(input AuditInput) map[string]any {
	details := input.Details
	if details == nil {
		details = map[string]any{}
	}
	return map[string]any{
		"organization": organizationRecord(input.Organization), "actor": userRecord(input.ActorID),
		"action": input.Action, "target_kind": input.Target.Kind, "target_id": input.Target.ID,
		"target_label": input.Target.Label, "details": details,
	}
}

// RecordAudit appends an entry to the organization's audit log.
func (s *SurrealStore) RecordAudit(ctx context.Context, input AuditInput) error {
	return queryExec(ctx, s.DB, recordAuditStatement, recordAuditParams(input))
}

const auditSelection = `SELECT id, at, actor.handle AS actor_handle, actor.first_name AS actor_first_name,
	actor.last_name AS actor_last_name, action, target_kind, target_id, target_label, details
	FROM organization_audit WHERE organization = $organization`

// ListAudit returns up to limit entries older than before (all when before is
// zero), newest first.
func (s *SurrealStore) ListAudit(ctx context.Context, handle string, before time.Time, limit int) (*AuditPage, error) {
	limit = clampAuditLimit(limit)
	params := map[string]any{"organization": organizationRecord(handle), "limit": limit}
	statement := auditSelection
	if !before.IsZero() {
		// Bound as RFC 3339 text: a time.Time parameter does not compare against stored datetimes.
		statement += " AND at < <datetime>$before_time"
		params["before_time"] = before.UTC().Format(time.RFC3339Nano)
	}
	rows, err := queryRows[dbAuditEntry](ctx, s.DB, statement+" ORDER BY at DESC LIMIT $limit", params)
	if err != nil {
		return nil, err
	}
	return auditPage(rows, limit), nil
}

func clampAuditLimit(limit int) int {
	if limit <= 0 {
		return defaultAuditLimit
	}
	if limit > maxAuditLimit {
		return maxAuditLimit
	}
	return limit
}

func auditPage(rows []dbAuditEntry, limit int) *AuditPage {
	page := &AuditPage{Entries: make([]AuditEntry, 0, len(rows))}
	for _, row := range rows {
		page.Entries = append(page.Entries, row.toEntry())
	}
	if len(rows) < limit || len(rows) == 0 {
		return page
	}
	cursor := rows[len(rows)-1].At.Format(time.RFC3339Nano)
	page.NextCursor = &cursor
	return page
}
