package database

import (
	"context"
	"errors"
	"fmt"

	"github.com/neoworks/auth/access"
	surrealdb "github.com/surrealdb/surrealdb.go"
)

// FeedRecipient is a principal that may need to hear about a change.
type FeedRecipient struct {
	Type string
	ID   string
}

// FeedChange is one node or grant row that was created or updated, reduced to
// what routing it needs. It carries no content.
type FeedChange struct {
	Table      string
	Seq        int64
	Collection string
	OwnerID    string

	// NodeID and Ancestors locate a node change; for a grant change NodeID is
	// the node the grant is on.
	NodeID    string
	Ancestors []string

	// Principal and GrantedBy are set on grant changes only.
	Principal FeedRecipient
	GrantedBy FeedRecipient
}

func (change FeedChange) sameRowAndSeq(other FeedChange) bool {
	return change.Table == other.Table && change.NodeID == other.NodeID && change.Seq == other.Seq &&
		change.Principal == other.Principal
}

func (change FeedChange) isGrant() bool {
	return change.Table == feedTableGrant
}

// FeedRecipients lists the principals a change concerns. A node change goes to
// its owner and to everyone holding an active grant on the node, a whole-node
// grant on an ancestor, or the same on a live shortcut to the node, because
// those principals pull the node too. A grant change goes to the principal it
// names, the node's owner and whoever made the grant, which is who Pull
// returns the grant to, so a revoked principal hears of its loss.
func (s *SurrealStore) FeedRecipients(ctx context.Context, change FeedChange) ([]FeedRecipient, error) {
	if change.isGrant() {
		return grantRecipients(change), nil
	}
	return s.nodeRecipients(ctx, change)
}

func grantRecipients(change FeedChange) []FeedRecipient {
	return distinctRecipients([]FeedRecipient{
		change.Principal,
		{Type: access.PrincipalTypeUser, ID: change.OwnerID},
		change.GrantedBy,
	})
}

type shortcutReach struct {
	ID        string   `json:"id"`
	OwnerID   string   `json:"owner_id"`
	Ancestors []string `json:"ancestors"`
}

type grantHolder struct {
	PrincipalType string `json:"principal_type"`
	PrincipalID   string `json:"principal_id"`
}

func (s *SurrealStore) nodeRecipients(ctx context.Context, change FeedChange) ([]FeedRecipient, error) {
	shortcuts, err := queryRows[shortcutReach](ctx, s.DB, shortcutsToNodeStatement, shortcutParams(change.NodeID))
	if err != nil {
		return nil, fmt.Errorf("feed shortcuts: %w", err)
	}
	nodeIDs := []string{change.NodeID}
	ancestorIDs := append([]string{}, change.Ancestors...)
	recipients := []FeedRecipient{{Type: access.PrincipalTypeUser, ID: change.OwnerID}}
	for _, shortcut := range shortcuts {
		nodeIDs = append(nodeIDs, shortcut.ID)
		ancestorIDs = append(ancestorIDs, shortcut.Ancestors...)
		recipients = append(recipients, FeedRecipient{Type: access.PrincipalTypeUser, ID: shortcut.OwnerID})
	}
	holders, err := queryRows[grantHolder](ctx, s.DB, grantHoldersStatement, grantHolderParams(nodeIDs, ancestorIDs))
	if err != nil {
		return nil, fmt.Errorf("feed grant holders: %w", err)
	}
	for _, holder := range holders {
		recipients = append(recipients, FeedRecipient{Type: holder.PrincipalType, ID: holder.PrincipalID})
	}
	return distinctRecipients(recipients), nil
}

func shortcutParams(nodeID string) map[string]any {
	return map[string]any{"node_id": nodeID}
}

func grantHolderParams(nodeIDs []string, ancestorIDs []string) map[string]any {
	return map[string]any{"node_ids": nodeIDs, "ancestor_ids": ancestorIDs}
}

const shortcutsToNodeStatement = `
SELECT record::id(id) AS id, owner_id, ancestors FROM node
WHERE target_id = $node_id AND deleted = false;`

const grantHoldersStatement = `
SELECT principal_type, principal_id FROM access_grant
WHERE revoked_at = NONE AND (node_id IN $node_ids OR (facets = NONE AND node_id IN $ancestor_ids));`

func distinctRecipients(recipients []FeedRecipient) []FeedRecipient {
	seen := map[FeedRecipient]bool{}
	distinct := []FeedRecipient{}
	for _, recipient := range recipients {
		if recipient.ID == "" || seen[recipient] {
			continue
		}
		seen[recipient] = true
		distinct = append(distinct, recipient)
	}
	return distinct
}

// FeedHead is the newest sequence the change counter has handed out.
func (s *SurrealStore) FeedHead(ctx context.Context) (int64, error) {
	results, err := surrealdb.Query[int64](ctx, s.DB, "SELECT VALUE seq FROM ONLY feed_state:main", nil)
	if err != nil {
		return 0, fmt.Errorf("feed head: %w", err)
	}
	if len(*results) == 0 {
		return 0, ErrNotFound
	}
	return (*results)[0].Result, nil
}

// HasChangesSince reports whether Pull would return anything to the principal
// after cursor. A cursor behind the purge horizon counts as a change, because
// the principal has to pull to learn it must start over.
func (s *SurrealStore) HasChangesSince(ctx context.Context, principal access.Principal, cursor int64) (bool, error) {
	page, err := s.Pull(ctx, principal, cursor, 1)
	var purged *PurgedError
	if errors.As(err, &purged) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return len(page.Nodes)+len(page.Grants)+len(page.AccessLog) > 0, nil
}
