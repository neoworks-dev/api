package database

import (
	"context"
	"fmt"

	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/accesslog"
)

const (
	DefaultPullLimit = 200
	MaxPullLimit     = 500
)

// PullPage is one page of the change feed.
type PullPage struct {
	Nodes     []Node            `json:"nodes"`
	Grants    []AccessGrant     `json:"grants"`
	AccessLog []accesslog.Entry `json:"accessLog"`
	Cursor    int64             `json:"cursor"`
	HasMore   bool              `json:"hasMore"`
}

type dbPullSnapshot struct {
	Head     int64           `json:"head"`
	Horizons []int64         `json:"horizons"`
	Nodes    []dbNode        `json:"nodes"`
	Grants   []dbAccessGrant `json:"grants"`
	Log      []dbAccessLog   `json:"log"`
}

// Pull returns the changes after cursor that the principal may see: nodes with
// an active grant on the node itself or a whole-node grant on an ancestor,
// restricted to the collections the token's scopes allow reading, and the grants
// addressed to the principal, made by it, or on nodes it owns, and the access
// log entries of the visible nodes. A user also sees every node it owns. A cursor of 0 is a full
// sync. A non-zero cursor older than the purge horizon of any owner whose nodes
// the principal can reach gets a PurgedError.
func (s *SurrealStore) Pull(ctx context.Context, principal access.Principal, cursor int64, limit int) (*PullPage, error) {
	limit = clampLimit(limit)
	snapshot, err := queryReturned[dbPullSnapshot](ctx, s.DB, pullStatement, pullParams(principal, cursor, limit))
	if err != nil {
		return nil, fmt.Errorf("pull: %w", err)
	}
	if horizon := maxHorizon(snapshot.Horizons); cursor != 0 && cursor < horizon {
		return nil, &PurgedError{Horizon: horizon}
	}
	return assemblePage(snapshot, limit), nil
}

func clampLimit(limit int) int {
	if limit < 1 {
		return DefaultPullLimit
	}
	if limit > MaxPullLimit {
		return MaxPullLimit
	}
	return limit
}

// ownerFilter is the user whose own nodes the principal sees without a grant.
// It is empty for installs, which match no owner.
func ownerFilter(principal access.Principal) string {
	if principal.IsInstall() {
		return ""
	}
	return principal.UserID
}

func maxHorizon(horizons []int64) int64 {
	var highest int64
	for _, horizon := range horizons {
		if horizon > highest {
			highest = horizon
		}
	}
	return highest
}

func pullParams(principal access.Principal, cursor int64, limit int) map[string]any {
	return map[string]any{
		"principal_type":   principal.Type(),
		"principal_id":     principal.ID(),
		"cursor":           cursor,
		"fetch":            limit + 1,
		"read_collections": principal.ReadableCollections(),
		"owner_filter":     ownerFilter(principal),
	}
}

// assemblePage trims the over-fetched lists to a common upper seq so the cursor
// is exact, and moves the cursor to the feed head once nothing is left.
func assemblePage(snapshot *dbPullSnapshot, limit int) *PullPage {
	pageEnd := snapshot.Head
	hasMore := false
	for _, lastSeq := range overflowSeqs(snapshot, limit) {
		pageEnd = min(pageEnd, lastSeq)
		hasMore = true
	}

	page := &PullPage{Nodes: []Node{}, Grants: []AccessGrant{}, AccessLog: []accesslog.Entry{}, Cursor: pageEnd, HasMore: hasMore}
	for _, row := range snapshot.Nodes {
		if row.Seq <= pageEnd {
			page.Nodes = append(page.Nodes, row.toNode())
		}
	}
	for _, row := range snapshot.Grants {
		if row.Seq <= pageEnd {
			page.Grants = append(page.Grants, row.toGrant())
		}
	}
	for _, row := range snapshot.Log {
		if row.Seq <= pageEnd {
			page.AccessLog = append(page.AccessLog, row.toEntry())
		}
	}
	return page
}

// overflowSeqs returns, for each list that held more than limit rows, the seq
// of its last row within the limit.
func overflowSeqs(snapshot *dbPullSnapshot, limit int) []int64 {
	seqs := []int64{}
	if len(snapshot.Nodes) > limit {
		seqs = append(seqs, snapshot.Nodes[limit-1].Seq)
	}
	if len(snapshot.Grants) > limit {
		seqs = append(seqs, snapshot.Grants[limit-1].Seq)
	}
	if len(snapshot.Log) > limit {
		seqs = append(seqs, snapshot.Log[limit-1].Seq)
	}
	return seqs
}

// pullStatement reads the feed head, the principal's reach and the next page in
// one transaction, so the head and the rows come from the same snapshot.
const pullStatement = `
BEGIN TRANSACTION;
LET $head = (SELECT VALUE seq FROM ONLY feed_state:main);
LET $whole = (SELECT VALUE node_id FROM access_grant
	WHERE principal_type = $principal_type AND principal_id = $principal_id
	AND revoked_at = NONE AND facets = NONE);
LET $partial = (SELECT VALUE node_id FROM access_grant
	WHERE principal_type = $principal_type AND principal_id = $principal_id
	AND revoked_at = NONE AND facets != NONE);
LET $reachable = array::concat($whole, $partial);
LET $owners = array::append(
	array::distinct(array::map($reachable, |$node_id| type::record('node', $node_id).owner_id)),
	$owner_filter);
LET $horizons = (SELECT VALUE seq FROM purge_horizon WHERE user_id IN $owners);
LET $nodes = (SELECT * FROM node
	WHERE seq > $cursor AND collection IN $read_collections
	AND (record::id(id) IN $reachable OR ancestors CONTAINSANY $whole OR owner_id = $owner_filter)
	ORDER BY seq ASC LIMIT $fetch);
LET $grants = (SELECT * FROM access_grant
	WHERE seq > $cursor AND collection IN $read_collections
	AND ((principal_type = $principal_type AND principal_id = $principal_id)
		OR owner_id = $owner_filter OR granted_by_id = $owner_filter)
	ORDER BY seq ASC LIMIT $fetch);
LET $log = (SELECT * FROM access_log
	WHERE seq > $cursor AND collection IN $read_collections
	AND (node_id IN $reachable OR node_ancestors CONTAINSANY $whole OR owner_id = $owner_filter)
	ORDER BY seq ASC LIMIT $fetch);
RETURN { head: $head, horizons: $horizons, nodes: $nodes, grants: $grants, log: $log };
COMMIT TRANSACTION;`

// PullLink returns the subtree shared by a link, page by page, without a
// principal. A revoked or unknown link is ErrNotFound.
func (s *SurrealStore) PullLink(ctx context.Context, linkID string, cursor int64, limit int) (*PullPage, error) {
	link, err := s.getLink(ctx, linkID)
	if err != nil || link.RevokedAt != nil {
		return nil, ErrNotFound
	}
	limit = clampLimit(limit)
	snapshot, err := queryReturned[dbPullSnapshot](ctx, s.DB, linkPullStatement, map[string]any{
		"node_id": link.NodeID,
		"cursor":  cursor,
		"fetch":   limit + 1,
	})
	if err != nil {
		return nil, fmt.Errorf("pull link: %w", err)
	}
	if horizon := maxHorizon(snapshot.Horizons); cursor != 0 && cursor < horizon {
		return nil, &PurgedError{Horizon: horizon}
	}
	return assemblePage(snapshot, limit), nil
}

const linkPullStatement = `
BEGIN TRANSACTION;
LET $head = (SELECT VALUE seq FROM ONLY feed_state:main);
LET $owner_id = (SELECT VALUE owner_id FROM ONLY type::record('node', $node_id));
LET $horizons = (SELECT VALUE seq FROM purge_horizon WHERE user_id = $owner_id);
LET $nodes = (SELECT * FROM node
	WHERE seq > $cursor AND (record::id(id) = $node_id OR $node_id IN ancestors)
	ORDER BY seq ASC LIMIT $fetch);
RETURN { head: $head, horizons: $horizons, nodes: $nodes, grants: [], log: [] };
COMMIT TRANSACTION;`
