package database_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/accesslog"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
)

func TestOwnerCreatesRootAndChildAndPullsBoth(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")

	child := newNode(owner, owner.UserID, "@neoworks/calendar", database.KindItem, &root.ID)
	f.pushOK(owner, child)

	page := f.pull(owner, 0, 100)
	ids := nodeIDs(page.Nodes)
	if !ids[root.ID] || !ids[child.ID] {
		t.Fatalf("pull missing nodes: %v", ids)
	}
	if len(page.Grants) != 1 || page.HasMore {
		t.Fatalf("expected the owner's own grant and no more pages, got %d grants hasMore=%v", len(page.Grants), page.HasMore)
	}
}

func TestPushRequiresWriteOnSelfOrAncestor(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	stranger := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")

	child := newNode(stranger, owner.UserID, "@neoworks/calendar", database.KindItem, &root.ID)
	if outcome := f.push(stranger, child); outcome.Status != database.StatusForbidden {
		t.Fatalf("stranger push: got %s want forbidden", outcome.Status)
	}

	readOnly := readGrant(access.PrincipalTypeUser, stranger.UserID, 1)
	f.grant(owner, root.ID, readOnly)
	if outcome := f.push(stranger, child); outcome.Status != database.StatusForbidden {
		t.Fatalf("reader push: got %s want forbidden", outcome.Status)
	}

	f.grant(owner, root.ID, writeGrant(access.PrincipalTypeUser, stranger.UserID, 1))
	if outcome := f.push(stranger, child); outcome.Status != database.StatusOK {
		t.Fatalf("writer push: got %s want ok", outcome.Status)
	}
}

func TestTokenScopeCapsGrantRole(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")

	readScoped := userPrincipal(owner.UserID, "@neoworks/calendar:read")
	child := newNode(readScoped, owner.UserID, "@neoworks/calendar", database.KindItem, &root.ID)
	if outcome := f.push(readScoped, child); outcome.Status != database.StatusForbidden {
		t.Fatalf("read-scoped push: got %s want forbidden", outcome.Status)
	}

	otherCollection := userPrincipal(owner.UserID, "@neoworks/photos:write")
	if page := f.pull(otherCollection, 0, 10); len(page.Nodes) != 0 {
		t.Fatalf("photos-scoped token pulled %d calendar nodes", len(page.Nodes))
	}
}

func TestBaseSeqConflictReturnsCurrent(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")

	item := newNode(owner, owner.UserID, "@neoworks/calendar", database.KindItem, &root.ID)
	firstSeq := f.pushOK(owner, item)

	stale := item
	stale.BaseSeq = 0
	outcome := f.push(owner, stale)
	if outcome.Status != database.StatusConflict || outcome.Current == nil || outcome.Current.Seq != firstSeq {
		t.Fatalf("expected conflict with current seq %d, got %+v", firstSeq, outcome)
	}

	next := item
	next.BaseSeq = firstSeq
	next.Content = dbtest.Content("ct2")
	secondSeq := f.pushOK(owner, next)
	if secondSeq <= firstSeq {
		t.Fatalf("seq did not advance: %d then %d", firstSeq, secondSeq)
	}
}

func TestVersionsKeepEveryAcceptedWrite(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")
	item := newNode(owner, owner.UserID, "@neoworks/calendar", database.KindItem, &root.ID)
	seq := f.pushOK(owner, item)
	item.BaseSeq = seq
	f.pushOK(owner, item)

	versions, err := f.store.ListNodeVersions(t.Context(), owner, item.ID)
	if err != nil {
		t.Fatalf("versions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(versions))
	}
}

func TestSubtreeGrantCoversDescendantsButFacetGrantDoesNot(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	reader := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")
	container := newNode(owner, owner.UserID, "@neoworks/calendar", database.KindContainer, &root.ID)
	f.pushOK(owner, container)
	item := newNode(owner, owner.UserID, "@neoworks/calendar", database.KindItem, &container.ID)
	f.pushOK(owner, item)

	facetGrant := readGrant(access.PrincipalTypeUser, reader.UserID, 1)
	facetGrant.Facets = []int{1}
	f.grant(owner, container.ID, facetGrant)
	ids := nodeIDs(f.pull(reader, 0, 100).Nodes)
	if !ids[container.ID] || ids[item.ID] || ids[root.ID] {
		t.Fatalf("facet grant should reach only its own node, got %v", ids)
	}

	facetGrant.Facets = nil
	f.grant(owner, container.ID, facetGrant)
	ids = nodeIDs(f.pull(reader, 0, 100).Nodes)
	if !ids[container.ID] || !ids[item.ID] || ids[root.ID] {
		t.Fatalf("subtree grant should reach container and item, got %v", ids)
	}
}

func TestNewGrantReDeliversExistingNodesToAnAlreadySyncedGrantee(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	reader := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")
	item := newNode(owner, owner.UserID, "@neoworks/calendar", database.KindItem, &root.ID)
	f.pushOK(owner, item)

	cursor := f.pull(reader, 0, 100).Cursor
	f.grant(owner, root.ID, readGrant(access.PrincipalTypeUser, reader.UserID, 1))

	page := f.pull(reader, cursor, 100)
	ids := nodeIDs(page.Nodes)
	if !ids[root.ID] || !ids[item.ID] || len(page.Grants) != 1 {
		t.Fatalf("expected root, item and the grant after cursor %d, got nodes %v grants %d", cursor, ids, len(page.Grants))
	}
}

func TestOnlyTheOwnerGrantsToOtherUsers(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	writer := f.createUser()
	third := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")
	f.grant(owner, root.ID, writeGrant(access.PrincipalTypeUser, writer.UserID, 1))

	if _, err := f.tryGrant(writer, root.ID, readGrant(access.PrincipalTypeUser, third.UserID, 1)); !errors.Is(err, database.ErrForbidden) {
		t.Fatalf("a writer sharing with another user: got %v want forbidden", err)
	}
	if _, err := f.tryGrant(third, root.ID, readGrant(access.PrincipalTypeUser, third.UserID, 1)); !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("an outsider granting: got %v want not found", err)
	}
	if err := f.tryRevoke(writer, root.ID, access.PrincipalTypeUser, owner.UserID); !errors.Is(err, database.ErrForbidden) {
		t.Fatalf("a writer revoking the owner: got %v want forbidden", err)
	}
}

func TestRevokeRules(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	writer := f.createUser()
	other := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")
	f.grant(owner, root.ID, writeGrant(access.PrincipalTypeUser, writer.UserID, 1))
	f.grant(owner, root.ID, readGrant(access.PrincipalTypeUser, other.UserID, 1))
	app, _ := f.createInstall(writer, "@neoworks/calendar:write")
	f.grant(writer, root.ID, writeGrant(access.PrincipalTypeInstall, app.InstallID, 1))

	if err := f.tryRevoke(writer, root.ID, access.PrincipalTypeUser, other.UserID); !errors.Is(err, database.ErrForbidden) {
		t.Fatalf("revoking someone else's grant: got %v want forbidden", err)
	}
	f.revoke(writer, root.ID, access.PrincipalTypeInstall, app.InstallID)
	f.revoke(writer, root.ID, access.PrincipalTypeUser, writer.UserID)
	f.revoke(owner, root.ID, access.PrincipalTypeUser, other.UserID)
	if err := f.tryRevoke(owner, root.ID, access.PrincipalTypeUser, other.UserID); !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("revoking an already revoked grant: got %v want not found", err)
	}
}

func TestGrantMustMatchNodeEpoch(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	reader := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")

	_, err := f.tryGrant(owner, root.ID, readGrant(access.PrincipalTypeUser, reader.UserID, 2))
	if !errors.Is(err, database.ErrStaleEpoch) {
		t.Fatalf("got %v want stale epoch", err)
	}
}

func TestRevokedGrantStopsAccessAndFlagsRotation(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	reader := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")
	f.grant(owner, root.ID, readGrant(access.PrincipalTypeUser, reader.UserID, 1))
	if len(f.pull(reader, 0, 10).Nodes) != 1 {
		t.Fatal("reader should see the root")
	}

	f.revoke(owner, root.ID, access.PrincipalTypeUser, reader.UserID)
	page := f.pull(reader, 0, 10)
	if len(page.Nodes) != 0 {
		t.Fatalf("revoked reader still pulls %d nodes", len(page.Nodes))
	}
	if len(page.Grants) != 1 || page.Grants[0].RevokedAt == nil {
		t.Fatalf("reader should be told the grant was revoked: %+v", page.Grants)
	}
	ownerView := f.pull(owner, 0, 10)
	if !ownerView.Nodes[0].NeedsRotation {
		t.Fatal("revoking should flag the node for rotation")
	}
}

func TestOwnersGrantToThemselvesIsEntryZero(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	stranger := f.createUser()
	root := newNode(owner, owner.UserID, "@neoworks/calendar", database.KindRoot, nil)
	f.pushOK(owner, root)

	if _, err := f.tryGrant(stranger, root.ID, writeGrant(access.PrincipalTypeUser, stranger.UserID, 1)); !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("a stranger's grant: got %v want not found", err)
	}
	result := f.grant(owner, root.ID, writeGrant(access.PrincipalTypeUser, owner.UserID, 1))
	if result.Entry.Index != 0 || result.Entry.PrevHash != accesslog.GenesisPrevHash || result.Grant.LogIndex != 0 {
		t.Fatalf("bootstrap grant should be entry 0: %+v", result)
	}
	entries, err := f.store.ListAccessLog(t.Context(), owner, root.ID)
	if err != nil || len(entries) != 1 || entries[0].EntryHash != result.Entry.EntryHash {
		t.Fatalf("log after bootstrap: %+v %v", entries, err)
	}
}

func TestAccessLogChainsEntriesAndRejectsAMovedHead(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	reader := f.createUser()
	other := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")
	account := f.accountOf(owner)

	first := f.grant(owner, root.ID, readGrant(access.PrincipalTypeUser, reader.UserID, 1))
	if first.Entry.Index != 1 {
		t.Fatalf("second entry of the chain should have index 1, got %d", first.Entry.Index)
	}
	entries, _ := f.store.ListAccessLog(t.Context(), owner, root.ID)
	if len(entries) != 2 || entries[1].PrevHash != entries[0].EntryHash {
		t.Fatalf("entries must chain: %+v", entries)
	}

	stale := account.GrantRequestAt(t, root.ID, readGrant(access.PrincipalTypeUser, other.UserID, 1), 1, entries[0].EntryHash)
	_, err := f.store.CreateAccessGrant(t.Context(), owner, root.ID, stale)
	var moved *database.LogHeadMovedError
	if !errors.As(err, &moved) || moved.Head == nil || moved.Head.Index != 1 || moved.Head.EntryHash != entries[1].EntryHash {
		t.Fatalf("stale head: got %v want log_head_moved reporting index 1", err)
	}
	wrongPrev := account.GrantRequestAt(t, root.ID, readGrant(access.PrincipalTypeUser, other.UserID, 1), 2, entries[0].EntryHash)
	if _, err := f.store.CreateAccessGrant(t.Context(), owner, root.ID, wrongPrev); !errors.As(err, &moved) {
		t.Fatalf("right index but wrong prevHash: got %v want log_head_moved", err)
	}
	if reader := f.pull(other, 0, 10); len(reader.Grants) != 0 {
		t.Fatal("a rejected entry must not store a grant")
	}
}

func TestEntriesMustBeSignedByTheActingUserAndDescribeTheGrant(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	reader := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")
	ctx := t.Context()
	input := readGrant(access.PrincipalTypeUser, reader.UserID, 1)

	forged := f.accountOf(reader).GrantRequest(t, f.store, root.ID, input)
	forged.Entry.ActorID = owner.UserID
	if _, err := f.store.CreateAccessGrant(ctx, owner, root.ID, forged); !errors.Is(err, database.ErrInvalidInput) {
		t.Fatalf("an entry signed by another key: got %v want invalid input", err)
	}

	request := f.accountOf(owner).GrantRequest(t, f.store, root.ID, input)
	request.Grant.Role = access.RoleWrite
	if _, err := f.store.CreateAccessGrant(ctx, owner, root.ID, request); !errors.Is(err, database.ErrInvalidInput) {
		t.Fatalf("a grant that differs from its entry: got %v want invalid input", err)
	}

	tampered := f.accountOf(owner).GrantRequest(t, f.store, root.ID, input)
	tampered.Entry.Epoch = 1
	tampered.Entry.Index = 5
	if _, err := f.store.CreateAccessGrant(ctx, owner, root.ID, tampered); !errors.Is(err, database.ErrInvalidInput) {
		t.Fatalf("changed entry bytes: got %v want invalid input", err)
	}
}

func TestInstallsCannotSubmitTheUsersSignedEntries(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	reader := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")
	app, _ := f.createInstall(owner, "@neoworks/calendar:write")
	f.grant(owner, root.ID, writeGrant(access.PrincipalTypeInstall, app.InstallID, 1))

	request := f.accountOf(owner).GrantRequest(t, f.store, root.ID, readGrant(access.PrincipalTypeUser, reader.UserID, 1))
	if _, err := f.store.CreateAccessGrant(t.Context(), app, root.ID, request); !errors.Is(err, database.ErrInvalidInput) {
		t.Fatalf("an install submitting the user's entry: got %v want invalid input", err)
	}
}

func TestUsersPassSharesToTheirOwnInstallsWithAtMostTheirRole(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	reader := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")
	f.grant(owner, root.ID, readGrant(access.PrincipalTypeUser, reader.UserID, 1))
	app, _ := f.createInstall(reader, "@neoworks/calendar:write")
	foreign, _ := f.createInstall(owner, "@neoworks/calendar:write")

	if _, err := f.tryGrant(reader, root.ID, writeGrant(access.PrincipalTypeInstall, app.InstallID, 1)); !errors.Is(err, database.ErrForbidden) {
		t.Fatalf("a reader granting write to their install: got %v want forbidden", err)
	}
	if _, err := f.tryGrant(reader, root.ID, readGrant(access.PrincipalTypeInstall, foreign.InstallID, 1)); !errors.Is(err, database.ErrForbidden) {
		t.Fatalf("granting someone else's install: got %v want forbidden", err)
	}
	f.grant(reader, root.ID, readGrant(access.PrincipalTypeInstall, app.InstallID, 1))
	if page := f.pull(app, 0, 10); len(page.Nodes) != 1 {
		t.Fatalf("the install should pull the shared root, got %d nodes", len(page.Nodes))
	}
}

func TestFacetSharesCanOnlyBePassedOnAsASubset(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	reader := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")
	item := newNode(owner, owner.UserID, "@neoworks/calendar", database.KindItem, &root.ID)
	f.pushOK(owner, item)
	shared := readGrant(access.PrincipalTypeUser, reader.UserID, 1)
	shared.Facets = []int{1}
	f.grant(owner, item.ID, shared)
	app, _ := f.createInstall(reader, "@neoworks/calendar:read")

	whole := readGrant(access.PrincipalTypeInstall, app.InstallID, 1)
	if _, err := f.tryGrant(reader, item.ID, whole); !errors.Is(err, database.ErrForbidden) {
		t.Fatalf("whole-node pass-on of a facet share: got %v want forbidden", err)
	}
	wider := whole
	wider.Facets = []int{1, 2}
	if _, err := f.tryGrant(reader, item.ID, wider); !errors.Is(err, database.ErrForbidden) {
		t.Fatalf("wider facets: got %v want forbidden", err)
	}
	subset := whole
	subset.Facets = []int{1}
	f.grant(reader, item.ID, subset)
}

func TestOwnerWritesWithoutAGrantButNotThroughAnInstallWithoutOne(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := newNode(owner, owner.UserID, "@neoworks/calendar", database.KindRoot, nil)
	f.pushOK(owner, root)
	item := newNode(owner, owner.UserID, "@neoworks/calendar", database.KindItem, &root.ID)
	if outcome := f.push(owner, item); outcome.Status != database.StatusOK {
		t.Fatalf("the owner writes in their own tree without any grant: got %s", outcome.Status)
	}
	if page := f.pull(owner, 0, 10); len(page.Nodes) != 2 {
		t.Fatalf("the owner pulls their own nodes without a grant, got %d", len(page.Nodes))
	}
	app, certID := f.createInstall(owner, "@neoworks/calendar:write")
	byInstall := newNode(app, owner.UserID, "@neoworks/calendar", database.KindItem, &root.ID)
	byInstall.CertID = &certID
	if outcome := f.push(app, byInstall); outcome.Status != database.StatusForbidden {
		t.Fatalf("an install has no implicit access: got %s want forbidden", outcome.Status)
	}
}

func TestPaginationAdvancesCursorWithoutSkipping(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")
	for index := 0; index < 5; index++ {
		f.pushOK(owner, newNode(owner, owner.UserID, "@neoworks/calendar", database.KindItem, &root.ID))
	}

	seen := map[string]bool{}
	var cursor int64
	for pages := 0; pages < 10; pages++ {
		page := f.pull(owner, cursor, 2)
		for id := range nodeIDs(page.Nodes) {
			seen[id] = true
		}
		cursor = page.Cursor
		if !page.HasMore {
			break
		}
	}
	if len(seen) != 6 {
		t.Fatalf("paged through %d nodes, want 6", len(seen))
	}
	if again := f.pull(owner, cursor, 2); len(again.Nodes) != 0 || again.HasMore {
		t.Fatalf("caught-up pull should be empty, got %d nodes", len(again.Nodes))
	}
}

func TestMovingAContainerMovesItsSubtreeAccess(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	reader := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")
	shared := newNode(owner, owner.UserID, "@neoworks/calendar", database.KindContainer, &root.ID)
	f.pushOK(owner, shared)
	private := newNode(owner, owner.UserID, "@neoworks/calendar", database.KindContainer, &root.ID)
	f.pushOK(owner, private)
	item := newNode(owner, owner.UserID, "@neoworks/calendar", database.KindItem, &private.ID)
	f.pushOK(owner, item)

	f.grant(owner, shared.ID, readGrant(access.PrincipalTypeUser, reader.UserID, 1))
	if nodeIDs(f.pull(reader, 0, 50).Nodes)[item.ID] {
		t.Fatal("reader must not see the private item yet")
	}

	cursor := f.pull(reader, 0, 50).Cursor
	moved := private
	moved.ParentID = &shared.ID
	moved.BaseSeq = f.nodeSeq(f.pull(owner, 0, 50), private.ID)
	f.pushOK(owner, moved)

	ids := nodeIDs(f.pull(reader, cursor, 50).Nodes)
	if !ids[private.ID] || !ids[item.ID] {
		t.Fatalf("moved subtree should reach the reader, got %v", ids)
	}
}

// Other services insert roots and grants directly at signup and consent. Whatever
// seq they supply must not matter: the counter assigns it, so two accounts never
// collide and the feed order stays global.
func TestDirectInsertsGetSeqFromTheCounter(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rootRow := func(owner string) map[string]any {
		return map[string]any{
			"id": uuid.NewString(), "owner_id": owner, "collection": "@neoworks/calendar", "kind": "root", "epoch": 1,
			"content": "", "base_seq": 0, "seq": 1,
			"author_type": "user", "author_id": owner, "signature": "sig",
		}
	}
	first, second := uuid.NewString(), uuid.NewString()
	rows := []map[string]any{rootRow(first), rootRow(second)}
	grantFor := func(row map[string]any, owner string) map[string]any {
		return map[string]any{
			"node_id": row["id"], "principal_type": "user", "principal_id": owner, "role": "write", "epoch": 1,
			"wrapped_keys": "wk", "granted_by_type": "user", "granted_by_id": owner, "signature": "gs", "log_index": 0,
		}
	}
	if err := queryAll(ctx, f, "INSERT INTO node $rows", map[string]any{"rows": rows}); err != nil {
		t.Fatalf("insert nodes: %v", err)
	}
	grants := []map[string]any{grantFor(rows[0], first), grantFor(rows[1], second)}
	if err := queryAll(ctx, f, "INSERT INTO access_grant $rows", map[string]any{"rows": grants}); err != nil {
		t.Fatalf("insert grants: %v", err)
	}

	page := f.pull(userPrincipal(first, "@neoworks/calendar:read"), 0, 10)
	if len(page.Nodes) != 1 || len(page.Grants) != 1 {
		t.Fatalf("directly inserted root and grant should be pulled: %d nodes %d grants", len(page.Nodes), len(page.Grants))
	}
	other := f.pull(userPrincipal(second, "@neoworks/calendar:read"), 0, 10)
	if page.Nodes[0].Seq == other.Nodes[0].Seq || page.Nodes[0].Seq == 1 && other.Nodes[0].Seq == 1 {
		t.Fatalf("supplied seq must be replaced by the counter: %d and %d", page.Nodes[0].Seq, other.Nodes[0].Seq)
	}
}

func TestGoogleNodesAreGatedByGoogleScopes(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := f.createRoot(owner, "@neoworks/google")

	if page := f.pull(owner, 0, 10); !nodeIDs(page.Nodes)[root.ID] {
		t.Fatal("a google-scoped token should pull the google root")
	}
	calendarOnly := userPrincipal(owner.UserID, "@neoworks/calendar:read", "@neoworks/calendar:write")
	if page := f.pull(calendarOnly, 0, 10); len(page.Nodes) != 0 {
		t.Fatalf("a calendar-scoped token pulled %d google nodes", len(page.Nodes))
	}
	child := newNode(calendarOnly, owner.UserID, "@neoworks/google", database.KindItem, &root.ID)
	if outcome := f.push(calendarOnly, child); outcome.Status != database.StatusForbidden {
		t.Fatalf("a calendar-scoped push into google: got %s want forbidden", outcome.Status)
	}
	readOnly := userPrincipal(owner.UserID, "@neoworks/google:read")
	if outcome := f.push(readOnly, child); outcome.Status != database.StatusForbidden {
		t.Fatalf("a google:read push: got %s want forbidden", outcome.Status)
	}
}

func TestPullReturnsTheAccessLogOfVisibleNodes(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	reader := f.createUser()
	stranger := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")
	f.grant(owner, root.ID, readGrant(access.PrincipalTypeUser, reader.UserID, 1))

	ownerPage := f.pull(owner, 0, 50)
	if len(ownerPage.AccessLog) != 2 {
		t.Fatalf("the owner sees both entries, got %d", len(ownerPage.AccessLog))
	}
	readerPage := f.pull(reader, 0, 50)
	if len(readerPage.AccessLog) != 2 || readerPage.Grants[0].LogIndex != 1 {
		t.Fatalf("a reader sees the chain and its grant's logIndex: %d entries, grants %+v", len(readerPage.AccessLog), readerPage.Grants)
	}
	if page := f.pull(stranger, 0, 50); len(page.AccessLog) != 0 {
		t.Fatalf("a stranger sees no entries, got %d", len(page.AccessLog))
	}
	after := f.pull(reader, readerPage.Cursor, 50)
	if len(after.AccessLog) != 0 {
		t.Fatal("entries before the cursor are not repeated")
	}
	f.revoke(owner, root.ID, access.PrincipalTypeUser, reader.UserID)
	if page := f.pull(owner, ownerPage.Cursor, 50); len(page.AccessLog) != 1 || page.AccessLog[0].Action != "revoke" {
		t.Fatalf("the revoke entry should arrive after the cursor: %+v", page.AccessLog)
	}
}

func TestInstallGrantsMustNameTheInstallsOwnCertificate(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := f.createRoot(owner, "@neoworks/calendar")
	app, _ := f.createInstall(owner, "@neoworks/calendar:read")
	_, otherCertificate := f.createInstall(owner, "@neoworks/calendar:read")
	account := f.accountOf(owner)

	request := account.GrantRequest(t, f.store, root.ID, readGrant(access.PrincipalTypeInstall, app.InstallID, 1))
	request.Entry.CertID = &otherCertificate
	request.Entry = account.Resign(t, request.Entry)
	if _, err := f.store.CreateAccessGrant(context.Background(), owner, root.ID, request); !errors.Is(err, database.ErrForbidden) {
		t.Fatalf("a grant naming another install's certificate: got %v want forbidden", err)
	}
	result := f.grant(owner, root.ID, readGrant(access.PrincipalTypeInstall, app.InstallID, 1))
	if result.Entry.CertID == nil {
		t.Fatal("the stored entry must keep the install's certId")
	}
}
