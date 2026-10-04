package database

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/neoworks/auth/access"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// Link is an unauthenticated share of a node's subtree. The node key travels in
// the URL fragment and never reaches the server.
type Link struct {
	ID        string     `json:"id"`
	NodeID    string     `json:"nodeId"`
	CreatedAt time.Time  `json:"createdAt"`
	RevokedAt *time.Time `json:"revokedAt"`
}

type dbLink struct {
	ID        *models.RecordID `json:"id"`
	Node      *models.RecordID `json:"node"`
	CreatedAt time.Time        `json:"created_at"`
	RevokedAt *time.Time       `json:"revoked_at"`
}

func (row dbLink) toLink() Link {
	return Link{
		ID:        recordIDString(row.ID),
		NodeID:    recordIDString(row.Node),
		CreatedAt: row.CreatedAt,
		RevokedAt: row.RevokedAt,
	}
}

func (s *SurrealStore) getLink(ctx context.Context, linkID string) (*dbLink, error) {
	return queryFirst[dbLink](ctx, s.DB, "SELECT * FROM $link",
		map[string]any{"link": models.NewRecordID("link", linkID)})
}

// CreateLink shares a node's subtree by link. It needs admin on the node.
func (s *SurrealStore) CreateLink(ctx context.Context, principal access.Principal, nodeID string) (*Link, error) {
	if _, err := s.authorizeNode(ctx, principal, nodeID, access.RoleAdmin); err != nil {
		return nil, err
	}
	row, err := queryFirst[dbLink](ctx, s.DB,
		"CREATE $link SET node = $node, created_by = $user",
		map[string]any{
			"link": models.NewRecordID("link", uuid.NewString()),
			"node": models.NewRecordID("node", nodeID),
			"user": models.NewRecordID("user", principal.UserID),
		})
	if err != nil {
		return nil, fmt.Errorf("create link: %w", err)
	}
	link := row.toLink()
	return &link, nil
}

// RevokeLink disables a link. It needs admin on the linked node.
func (s *SurrealStore) RevokeLink(ctx context.Context, principal access.Principal, linkID string) error {
	row, err := s.getLink(ctx, linkID)
	if err != nil {
		return err
	}
	if _, err := s.authorizeNode(ctx, principal, recordIDString(row.Node), access.RoleAdmin); err != nil {
		return err
	}
	return queryExec(ctx, s.DB, "UPDATE $link SET revoked_at = time::now() WHERE revoked_at = NONE",
		map[string]any{"link": models.NewRecordID("link", linkID)})
}

// LinkedNode resolves an active link to the node it shares.
func (s *SurrealStore) LinkedNode(ctx context.Context, linkID string) (*dbNode, error) {
	link, err := s.getLink(ctx, linkID)
	if err != nil || link.RevokedAt != nil {
		return nil, ErrNotFound
	}
	return s.getNodeRow(ctx, recordIDString(link.Node))
}
