package database

import (
	"context"
	"fmt"

	"github.com/neoworks/auth/access"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

func (s *SurrealStore) getNodeRow(ctx context.Context, nodeID string) (*dbNode, error) {
	return queryFirst[dbNode](ctx, s.DB, "SELECT * FROM $node",
		map[string]any{"node": models.NewRecordID("node", nodeID)})
}

type grantReach struct {
	Role   string `json:"role"`
	Facets []int  `json:"facets"`
}

// authorizeNode returns the node when the principal holds at least the minimum
// role on it, with the token's scopes capping the grants' roles. A node the
// principal cannot even read is reported as ErrNotFound, so existence does not
// leak; a reader asking for more gets ErrForbidden.
func (s *SurrealStore) authorizeNode(ctx context.Context, principal access.Principal, nodeID, minimum string) (*dbNode, error) {
	node, err := s.getNodeRow(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	reaches, err := s.grantsReaching(ctx, principal, nodeID, node)
	if err != nil {
		return nil, err
	}
	if !holdsRole(reaches, principal.RolesUsable(node.Collection, access.RoleRead)) {
		return nil, ErrNotFound
	}
	if !holdsRole(reaches, principal.RolesUsable(node.Collection, minimum)) {
		return nil, ErrForbidden
	}
	return node, nil
}

// authorizeOwner returns the node when the principal is the user who owns it.
// Unreadable and foreign nodes are reported as not found.
func (s *SurrealStore) authorizeOwner(ctx context.Context, principal access.Principal, nodeID string) (*dbNode, error) {
	node, err := s.authorizeNode(ctx, principal, nodeID, access.RoleRead)
	if err != nil {
		return nil, err
	}
	if principal.IsInstall() || node.OwnerID != principal.UserID {
		return nil, ErrForbidden
	}
	return node, nil
}

// ownsNode reports whether the principal is the user who owns the node. The
// owner holds write on everything they own without a grant.
func ownsNode(principal access.Principal, node *dbNode) bool {
	return !principal.IsInstall() && node.OwnerID == principal.UserID
}

// grantsReaching lists what gives the principal access to the node: any grant
// on the node itself, whole-node grants on its ancestors, ownership, and live
// shortcuts to it, each capped at the role the shortcut passes on.
func (s *SurrealStore) grantsReaching(ctx context.Context, principal access.Principal, nodeID string, node *dbNode) ([]grantReach, error) {
	reaches, err := s.directReaches(ctx, principal, nodeID, node)
	if err != nil {
		return nil, err
	}
	throughShortcuts, err := s.reachesThroughShortcuts(ctx, principal, nodeID)
	if err != nil {
		return nil, err
	}
	return append(reaches, throughShortcuts...), nil
}

// directReaches lists the principal's grants on the node and whole-node grants
// on its ancestors, plus write when the principal owns the node.
func (s *SurrealStore) directReaches(ctx context.Context, principal access.Principal, nodeID string, node *dbNode) ([]grantReach, error) {
	rows, err := queryRows[grantReach](ctx, s.DB, `
		SELECT role, facets FROM access_grant
		WHERE principal_type = $principal_type AND principal_id = $principal_id
		AND revoked_at = NONE
		AND (node_id = $node_id OR (facets = NONE AND node_id IN $ancestors))`,
		map[string]any{
			"principal_type": principal.Type(),
			"principal_id":   principal.ID(),
			"node_id":        nodeID,
			"ancestors":      node.Ancestors,
		})
	if err != nil {
		return nil, fmt.Errorf("load grants: %w", err)
	}
	if ownsNode(principal, node) {
		rows = append(rows, grantReach{Role: access.RoleWrite})
	}
	return rows, nil
}

// reachesThroughShortcuts gives, for each live shortcut to the node that the
// principal reaches directly, the lower of its role there and the role the
// shortcut passes on, as a whole-node reach.
func (s *SurrealStore) reachesThroughShortcuts(ctx context.Context, principal access.Principal, nodeID string) ([]grantReach, error) {
	shortcuts, err := queryRows[dbNode](ctx, s.DB,
		"SELECT * FROM node WHERE target_id = $node_id AND deleted = false", map[string]any{"node_id": nodeID})
	if err != nil {
		return nil, fmt.Errorf("load shortcuts: %w", err)
	}
	reaches := []grantReach{}
	for index := range shortcuts {
		shortcut := &shortcuts[index]
		atShortcut, err := s.directReaches(ctx, principal, recordIDString(shortcut.ID), shortcut)
		if err != nil {
			return nil, err
		}
		reaches = append(reaches, cappedReaches(atShortcut, *shortcut.TargetRole)...)
	}
	return reaches, nil
}

func cappedReaches(reaches []grantReach, ceiling string) []grantReach {
	capped := make([]grantReach, 0, len(reaches))
	for _, reach := range reaches {
		capped = append(capped, grantReach{Role: access.LowerRole(reach.Role, ceiling)})
	}
	return capped
}

func holdsRole(reaches []grantReach, roles []string) bool {
	for _, reach := range reaches {
		if containsString(roles, reach.Role) {
			return true
		}
	}
	return false
}

// GetNodeForPrincipal returns a node the principal may read.
func (s *SurrealStore) GetNodeForPrincipal(ctx context.Context, principal access.Principal, nodeID string) (*Node, error) {
	row, err := s.authorizeNode(ctx, principal, nodeID, access.RoleRead)
	if err != nil {
		return nil, err
	}
	node := row.toNode()
	return &node, nil
}

// ListNodeVersions returns a node's history, oldest first, to a principal that
// may read the node.
func (s *SurrealStore) ListNodeVersions(ctx context.Context, principal access.Principal, nodeID string) ([]NodeVersion, error) {
	if _, err := s.authorizeNode(ctx, principal, nodeID, access.RoleRead); err != nil {
		return nil, err
	}
	rows, err := queryRows[dbNodeVersion](ctx, s.DB,
		"SELECT * FROM node_version WHERE node_id = $node_id ORDER BY seq ASC, created_at ASC",
		map[string]any{"node_id": nodeID})
	if err != nil {
		return nil, fmt.Errorf("list versions: %w", err)
	}
	versions := make([]NodeVersion, 0, len(rows))
	for _, row := range rows {
		versions = append(versions, row.toVersion())
	}
	return versions, nil
}
