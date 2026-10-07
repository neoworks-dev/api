package database_test

import (
	"context"

	"github.com/google/uuid"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
	surrealdb "github.com/surrealdb/surrealdb.go"
)

func newNode(author access.Principal, ownerID, collection, kind string, parentID *string) database.Node {
	node := database.Node{
		ID:         uuid.NewString(),
		ParentID:   parentID,
		OwnerID:    ownerID,
		Collection: collection,
		Kind:       kind,
		Epoch:      1,
		AuthorType: author.Type(),
		AuthorID:   author.ID(),
		Signature:  "sig",
	}
	if kind != database.KindRoot {
		wrapped := "wrapped"
		node.WrappedKey = &wrapped
		node.Content = dbtest.Content("ct")
	}
	return node
}

func (f *fixture) push(author access.Principal, node database.Node) *database.PushOutcome {
	f.t.Helper()
	dbtest.PublishNodeSchemas(f.t, f.store)
	validated, err := database.ValidateNodeInput(node, author)
	if err != nil {
		f.t.Fatalf("validate: %v", err)
	}
	outcome, err := f.store.PushNode(context.Background(), author, validated)
	if err != nil {
		f.t.Fatalf("push: %v", err)
	}
	return outcome
}

func (f *fixture) pushOK(author access.Principal, node database.Node) int64 {
	f.t.Helper()
	outcome := f.push(author, node)
	if outcome.Status != database.StatusOK {
		f.t.Fatalf("push %s: status %s", node.Kind, outcome.Status)
	}
	return outcome.Seq
}

func writeGrant(principalType, principalID string, epoch int) database.GrantInput {
	return dbtest.WriteGrant(principalType, principalID, epoch)
}

func readGrant(principalType, principalID string, epoch int) database.GrantInput {
	return dbtest.ReadGrant(principalType, principalID, epoch)
}

// grant signs and stores a grant by the user behind the principal.
func (f *fixture) grant(by access.Principal, nodeID string, input database.GrantInput) *database.GrantResult {
	f.t.Helper()
	return f.accountOf(by).Grant(f.t, f.store, nodeID, input)
}

func (f *fixture) tryGrant(by access.Principal, nodeID string, input database.GrantInput) (*database.GrantResult, error) {
	f.t.Helper()
	request := f.accountOf(by).GrantRequest(f.t, f.store, nodeID, input)
	return f.store.CreateAccessGrant(context.Background(), by, nodeID, request)
}

func (f *fixture) revoke(by access.Principal, nodeID, principalType, principalID string) {
	f.t.Helper()
	f.accountOf(by).Revoke(f.t, f.store, nodeID, principalType, principalID)
}

func (f *fixture) tryRevoke(by access.Principal, nodeID, principalType, principalID string) error {
	f.t.Helper()
	entry := f.accountOf(by).RevokeEntry(f.t, f.store, nodeID, principalType, principalID)
	_, err := f.store.RevokeAccessGrant(context.Background(), by, nodeID, entry)
	return err
}

// createRoot pushes a root for the owner and records the owner's own grant as
// entry 0 of the root's log.
func (f *fixture) createRoot(owner access.Principal, collection string) database.Node {
	f.t.Helper()
	root := newNode(owner, owner.UserID, collection, database.KindRoot, nil)
	f.pushOK(owner, root)
	f.grant(owner, root.ID, writeGrant(access.PrincipalTypeUser, owner.UserID, 1))
	return root
}

func (f *fixture) pull(principal access.Principal, cursor int64, limit int) *database.PullPage {
	f.t.Helper()
	page, err := f.store.Pull(context.Background(), principal, cursor, limit)
	if err != nil {
		f.t.Fatalf("pull: %v", err)
	}
	return page
}

func nodeIDs(nodes []database.Node) map[string]bool {
	ids := map[string]bool{}
	for _, node := range nodes {
		ids[node.ID] = true
	}
	return ids
}

func (f *fixture) nodeSeq(page *database.PullPage, nodeID string) int64 {
	f.t.Helper()
	for _, node := range page.Nodes {
		if node.ID == nodeID {
			return node.Seq
		}
	}
	f.t.Fatalf("node %s not in page", nodeID)
	return 0
}

func queryAll(ctx context.Context, f *fixture, query string, params map[string]any) error {
	_, err := surrealdb.Query[[]any](ctx, f.store.DB, query, params)
	return err
}
