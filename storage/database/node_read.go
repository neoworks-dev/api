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
	Node   *models.RecordID `json:"node"`
	Role   string           `json:"role"`
	Facets []int            `json:"facets"`
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

// grantsReaching lists the principal's active grants that apply to the node: any
// grant on the node itself, and whole-node grants on its ancestors.
func (s *SurrealStore) grantsReaching(ctx context.Context, principal access.Principal, nodeID string, node *dbNode) ([]grantReach, error) {
	rows, err := queryRows[grantReach](ctx, s.DB, `
		SELECT node, role, facets FROM access_grant
		WHERE principal_type = $principal_type AND principal_id = $principal_id
		AND revoked_at = NONE
		AND (node = $node OR (facets = NONE AND node IN $ancestors))`,
		map[string]any{
			"principal_type": principal.Type(),
			"principal_id":   principal.ID(),
			"node":           models.NewRecordID("node", nodeID),
			"ancestors":      node.Ancestors,
		})
	if err != nil {
		return nil, fmt.Errorf("load grants: %w", err)
	}
	return rows, nil
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
		"SELECT * FROM node_version WHERE node = $node ORDER BY seq ASC, created_at ASC",
		map[string]any{"node": models.NewRecordID("node", nodeID)})
	if err != nil {
		return nil, fmt.Errorf("list versions: %w", err)
	}
	versions := make([]NodeVersion, 0, len(rows))
	for _, row := range rows {
		versions = append(versions, row.toVersion())
	}
	return versions, nil
}
