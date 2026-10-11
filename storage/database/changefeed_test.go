package database_test

import (
	"context"
	"net"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/storage/database"
	surrealdb "github.com/surrealdb/surrealdb.go"
)

func recipientIDs(recipients []database.FeedRecipient) []string {
	ids := []string{}
	for _, recipient := range recipients {
		ids = append(ids, recipient.ID)
	}
	slices.Sort(ids)
	return ids
}

func (f *fixture) recipientsOfNode(node database.Node) []string {
	f.t.Helper()
	change := database.FeedChange{Table: "node", NodeID: node.ID, OwnerID: node.OwnerID, Collection: node.Collection}
	if node.ParentID != nil {
		change.Ancestors = []string{*node.ParentID}
	}
	recipients, err := f.store.FeedRecipients(context.Background(), change)
	if err != nil {
		f.t.Fatalf("recipients: %v", err)
	}
	return recipientIDs(recipients)
}

func sortedIDs(ids ...string) []string {
	slices.Sort(ids)
	return ids
}

func TestNodeChangeGoesToTheOwnerAndGrantHoldersOfTheNodeOrAnAncestor(t *testing.T) {
	f := newFixture(t)
	owner, viewer, stranger := f.createUser(), f.createUser(), f.createUser()
	root := f.createRoot(owner, photos)
	child := newNode(owner, owner.UserID, photos, database.KindContainer, &root.ID)
	f.pushOK(owner, child)
	grandchild := newNode(owner, owner.UserID, photos, database.KindItem, &child.ID)
	f.pushOK(owner, grandchild)

	if got := f.recipientsOfNode(grandchild); !slices.Equal(got, sortedIDs(owner.UserID)) {
		t.Fatalf("before any grant only the owner hears: %v", got)
	}
	f.grant(owner, child.ID, readGrant(access.PrincipalTypeUser, viewer.UserID, 1))
	change := database.FeedChange{Table: "node", NodeID: grandchild.ID, OwnerID: owner.UserID, Ancestors: []string{root.ID, child.ID}}
	recipients, err := f.store.FeedRecipients(context.Background(), change)
	if err != nil {
		t.Fatal(err)
	}
	if got := recipientIDs(recipients); !slices.Equal(got, sortedIDs(owner.UserID, viewer.UserID)) {
		t.Fatalf("a whole-node grant on an ancestor reaches its holder, not %v (stranger %s)", got, stranger.UserID)
	}
}

func TestNodeChangeSkipsRevokedAndFacetOnlyGrants(t *testing.T) {
	f := newFixture(t)
	owner, revoked, partial := f.createUser(), f.createUser(), f.createUser()
	root := f.createRoot(owner, photos)
	child := newNode(owner, owner.UserID, photos, database.KindItem, &root.ID)
	f.pushOK(owner, child)
	f.grant(owner, root.ID, readGrant(access.PrincipalTypeUser, revoked.UserID, 1))
	facetGrant := readGrant(access.PrincipalTypeUser, partial.UserID, 1)
	facetGrant.Facets = []int{1}
	f.grant(owner, root.ID, facetGrant)
	f.revoke(owner, root.ID, access.PrincipalTypeUser, revoked.UserID)

	change := database.FeedChange{Table: "node", NodeID: child.ID, OwnerID: owner.UserID, Ancestors: []string{root.ID}}
	recipients, err := f.store.FeedRecipients(context.Background(), change)
	if err != nil {
		t.Fatal(err)
	}
	if got := recipientIDs(recipients); !slices.Equal(got, sortedIDs(owner.UserID)) {
		t.Fatalf("a revoked grant and a facet grant on an ancestor reach nobody: %v", got)
	}
	rootChange := database.FeedChange{Table: "node", NodeID: root.ID, OwnerID: owner.UserID}
	recipients, err = f.store.FeedRecipients(context.Background(), rootChange)
	if err != nil {
		t.Fatal(err)
	}
	if got := recipientIDs(recipients); !slices.Equal(got, sortedIDs(owner.UserID, partial.UserID)) {
		t.Fatalf("a facet grant reaches its holder for the node it is on: %v", got)
	}
}

func TestNodeChangeReachesTheHoldersOfShortcutsToIt(t *testing.T) {
	f := newFixture(t)
	scene := newAlbumWithPhoto(f)
	viewer := f.createUser()
	f.pushOK(scene.owner, shortcutTo(scene.owner, scene.owner.UserID, &scene.album.ID, scene.photo, access.RoleRead))
	f.grant(scene.owner, scene.album.ID, readGrant(access.PrincipalTypeUser, viewer.UserID, 1))

	change := database.FeedChange{Table: "node", NodeID: scene.photo.ID, OwnerID: scene.owner.UserID, Ancestors: []string{scene.root.ID, scene.library.ID}}
	recipients, err := f.store.FeedRecipients(context.Background(), change)
	if err != nil {
		t.Fatal(err)
	}
	if got := recipientIDs(recipients); !slices.Equal(got, sortedIDs(scene.owner.UserID, viewer.UserID)) {
		t.Fatalf("the album's viewer hears of changes to the photo it points at: %v", got)
	}
}

// awaitChanges reads until every predicate has matched a change and returns the
// matches in predicate order. Tables are watched by separate queries, so the
// changes of one write can arrive in either order.
func awaitChanges(t *testing.T, watch *database.FeedWatch, wanted ...func(database.FeedChange) bool) []database.FeedChange {
	t.Helper()
	matches := make([]*database.FeedChange, len(wanted))
	for !allMatched(matches) {
		change := receiveChange(t, watch)
		for index, predicate := range wanted {
			if matches[index] == nil && predicate(change) {
				matches[index] = &change
			}
		}
	}
	found := []database.FeedChange{}
	for _, match := range matches {
		found = append(found, *match)
	}
	return found
}

func allMatched(matches []*database.FeedChange) bool {
	for _, match := range matches {
		if match == nil {
			return false
		}
	}
	return true
}

func forTable(table string) func(database.FeedChange) bool {
	return func(change database.FeedChange) bool { return change.Table == table }
}

func forNode(nodeID string) func(database.FeedChange) bool {
	return func(change database.FeedChange) bool { return change.Table == "node" && change.NodeID == nodeID }
}

func receiveChange(t *testing.T, watch *database.FeedWatch) database.FeedChange {
	t.Helper()
	select {
	case change := <-watch.Changes():
		return change
	case <-time.After(5 * time.Second):
		t.Fatal("no change arrived")
		return database.FeedChange{}
	}
}

func TestWatchDeliversNodeAndGrantChangesWithoutContent(t *testing.T) {
	f := newFixture(t)
	owner, viewer := f.createUser(), f.createUser()
	watch, err := f.store.WatchFeed(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer watch.Close()

	root := f.createRoot(owner, photos)
	created := awaitChanges(t, watch, forNode(root.ID), forTable("access_grant"))
	rootChange, ownerGrant := created[0], created[1]
	if rootChange.OwnerID != owner.UserID || rootChange.Collection != photos {
		t.Fatalf("root change: %+v", rootChange)
	}
	if ownerGrant.Principal.ID != owner.UserID || ownerGrant.NodeID != root.ID {
		t.Fatalf("owner grant change: %+v", ownerGrant)
	}

	f.grant(owner, root.ID, readGrant(access.PrincipalTypeUser, viewer.UserID, 1))
	viewerGrant := awaitChanges(t, watch, func(change database.FeedChange) bool {
		return change.Table == "access_grant" && change.Principal.ID == viewer.UserID
	})[0]
	if viewerGrant.Principal.Type != "user" || viewerGrant.GrantedBy.ID != owner.UserID {
		t.Fatalf("viewer grant change: %+v", viewerGrant)
	}

	item := newNode(owner, owner.UserID, photos, database.KindItem, &root.ID)
	seq := f.pushOK(owner, item)
	itemChange := awaitChanges(t, watch, forNode(item.ID))[0]
	if itemChange.Seq != seq || !slices.Equal(itemChange.Ancestors, []string{root.ID}) {
		t.Fatalf("item change should carry seq %d and its ancestors: %+v", seq, itemChange)
	}
}

func TestWatchSeesARevokeAsAGrantChangeForTheRevokedPrincipal(t *testing.T) {
	f := newFixture(t)
	owner, viewer := f.createUser(), f.createUser()
	root := f.createRoot(owner, photos)
	f.grant(owner, root.ID, readGrant(access.PrincipalTypeUser, viewer.UserID, 1))
	watch, err := f.store.WatchFeed(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer watch.Close()

	f.revoke(owner, root.ID, access.PrincipalTypeUser, viewer.UserID)
	change := awaitChanges(t, watch, forTable("access_grant"))[0]
	recipients, err := f.store.FeedRecipients(context.Background(), change)
	if err != nil {
		t.Fatal(err)
	}
	if got := recipientIDs(recipients); !slices.Contains(got, viewer.UserID) || !slices.Contains(got, owner.UserID) {
		t.Fatalf("the revoked principal and the owner must hear of the revoke: %v", got)
	}
}

func TestFeedHeadAndChangesSince(t *testing.T) {
	f := newFixture(t)
	owner, stranger := f.createUser(), f.createUser()
	root := f.createRoot(owner, photos)
	ctx := context.Background()

	head, err := f.store.FeedHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head < 2 {
		t.Fatalf("a root and its grant take two sequences, head is %d", head)
	}
	changed, err := f.store.HasChangesSince(ctx, owner, head)
	if err != nil || changed {
		t.Fatalf("nothing happened after the head: changed=%v err=%v", changed, err)
	}
	f.pushOK(owner, newNode(owner, owner.UserID, photos, database.KindItem, &root.ID))
	changed, err = f.store.HasChangesSince(ctx, owner, head)
	if err != nil || !changed {
		t.Fatalf("the owner should see the new item: changed=%v err=%v", changed, err)
	}
	changed, err = f.store.HasChangesSince(ctx, stranger, head)
	if err != nil || changed {
		t.Fatalf("a stranger sees nothing: changed=%v err=%v", changed, err)
	}
}

func TestWatchIsLostWhenTheDatabaseGoesAway(t *testing.T) {
	if _, err := exec.LookPath("surreal"); err != nil {
		t.Skip("surreal binary not on PATH")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	server := exec.Command("surreal", "start", "--log", "error", "--user", "root", "--pass", "root", "--bind", address, "memory")
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })

	store := connectWhenReady(t, "ws://"+address)
	store.SetFeedProbeInterval(200 * time.Millisecond)
	if _, err := surrealdb.Query[any](context.Background(), store.DB, "DEFINE TABLE node; DEFINE TABLE access_grant;", nil); err != nil {
		t.Fatal(err)
	}
	watch, err := store.WatchFeed(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer watch.Close()

	_ = server.Process.Kill()
	select {
	case <-watch.Lost():
	case <-time.After(10 * time.Second):
		t.Fatal("the watch never noticed the database was gone")
	}
}

func connectWhenReady(t *testing.T, url string) *database.SurrealStore {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		store, err := database.NewSurrealStore(url, "root", "root", "test", "feed")
		if err == nil {
			return store
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("surreal did not become ready")
	return nil
}
