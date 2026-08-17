package database

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// newTestUUID mints an id of the shape the store now requires: spaces, items and
// versions are all uuid-keyed, because an item's record id embeds its space's.
func newTestUUID() string {
	return uuid.Must(uuid.NewV4()).String()
}

// oneVersion builds the history entry an ordinary edit appends.
func oneVersion(id string) []PushVersionParams {
	return []PushVersionParams{{VersionID: id, Blob: "v_" + id, Sig: "vs_" + id}}
}

func countItemVersions(t *testing.T, conn *surrealdb.DB, spaceID models.RecordID, itemID string) int {
	t.Helper()
	itemUUID, err := parseUUID(itemID)
	if err != nil {
		t.Fatalf("item id: %v", err)
	}
	results, err := surrealdb.Query[[]struct {
		Count int `json:"count"`
	}](context.Background(), conn, `
		LET $iid = $item_uuid;
		SELECT count() AS count FROM item_version WHERE space = $space AND item_id = $iid GROUP ALL`,
		map[string]any{"space": spaceID, "item_uuid": itemUUID},
	)
	if err != nil {
		t.Fatalf("count item_version: %v", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0].Count
		}
	}
	return 0
}

// TestItemPushPull covers the envelope write path: OCC on base_seq, version
// rows, tombstoning, epoch enforcement, authz roles, pull paging, and the purge
// horizon. Requires migrations 053/054.
func TestItemPushPull(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")

	suffix := randSuffix()
	owner := newSpaceTestUser(t, root, "ci_owner_"+suffix)
	reader := newSpaceTestUser(t, root, "ci_reader_"+suffix)
	cleanupSpaces(t, root, owner, reader)

	spaces := store.Spaces
	membership, err := spaces.Create(ctx, owner, CreateSpaceParams{
		SpaceID:    newTestUUID(),
		Collection: "contacts", Kind: "personal", WrappedKey: "wrap", Signature: "sig",
	})
	if err != nil {
		t.Fatalf("create space: %v", err)
	}
	spaceID := spaceRecord(t, membership.Space.ID)

	itemID := newTestUUID()
	firstVersion, secondVersion := newTestUUID(), newTestUUID()

	// Create: base_seq must be 0.
	if _, err := spaces.PushItem(ctx, spaceID, owner, PushItemParams{
		ItemID: itemID, BaseSeq: 7, KeyEpoch: 1, SchemaVer: 1, Blob: "ct1", Sig: "s1",
		Versions: oneVersion(firstVersion),
	}); !errors.Is(err, ErrSeqConflict) {
		t.Fatalf("create with nonzero base_seq: want conflict, got %v", err)
	}
	created, err := spaces.PushItem(ctx, spaceID, owner, PushItemParams{
		ItemID: itemID, BaseSeq: 0, KeyEpoch: 1, SchemaVer: 1, Blob: "ct1", Sig: "s1",
		Versions: oneVersion(firstVersion),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Seq != 1 {
		t.Fatalf("first item seq: want 1, got %d", created.Seq)
	}

	// Update with correct base_seq bumps seq and appends a second version.
	updated, err := spaces.PushItem(ctx, spaceID, owner, PushItemParams{
		ItemID: itemID, BaseSeq: 1, KeyEpoch: 1, SchemaVer: 1, Blob: "ct2", Sig: "s2",
		Versions: oneVersion(secondVersion),
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Seq != 2 {
		t.Fatalf("update seq: want 2, got %d", updated.Seq)
	}
	versions, err := spaces.ListItemVersions(ctx, spaceID, owner, itemID)
	if err != nil {
		t.Fatalf("versions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("want 2 versions after create+update, got %d", len(versions))
	}
	if versions[0].Seq != 1 || versions[0].VersionID != firstVersion {
		t.Fatalf("first version wrong: %+v", versions[0])
	}
	if versions[0].ItemID != itemID {
		t.Fatalf("version must carry its item uuid: %q vs %q", versions[0].ItemID, itemID)
	}
	if versions[1].Blob == nil || *versions[1].Blob != "v_"+secondVersion {
		t.Fatalf("second version blob wrong: %+v", versions[1])
	}

	// The head points at the newest version.
	head, err := spaces.GetItem(ctx, spaceID, owner, itemID)
	if err != nil {
		t.Fatalf("get head: %v", err)
	}
	if head.VersionID != secondVersion {
		t.Fatalf("head version: want %s, got %q", secondVersion, head.VersionID)
	}
	if head.ID != itemID {
		t.Fatalf("head id must render as the item uuid: %q", head.ID)
	}
	if head.SpaceID != membership.Space.ID {
		t.Fatalf("head space must render as the space uuid: %q vs %q", head.SpaceID, membership.Space.ID)
	}

	// Stale base_seq conflicts and returns the current row.
	outcome, err := spaces.PushItem(ctx, spaceID, owner, PushItemParams{
		ItemID: itemID, BaseSeq: 1, KeyEpoch: 1, SchemaVer: 1, Blob: "ct3", Sig: "s3",
		Versions: oneVersion(newTestUUID()),
	})
	if !errors.Is(err, ErrSeqConflict) {
		t.Fatalf("stale base_seq: want conflict, got %v", err)
	}
	if outcome.Current == nil || outcome.Current.Seq != 2 {
		t.Fatalf("conflict must carry current row: %+v", outcome.Current)
	}

	// Reader role cannot push.
	if _, err := spaces.InviteMember(ctx, spaceID, owner, InviteParams{
		MemberID: reader, Role: "reader",
		WrappedKeys: []WrappedKey{{Epoch: 1, WrappedKey: "w", Signature: "s"}},
	}); err != nil {
		t.Fatalf("invite reader: %v", err)
	}
	if err := spaces.Accept(ctx, spaceID, reader, "pin"); err != nil {
		t.Fatalf("accept reader: %v", err)
	}
	if _, err := spaces.PushItem(ctx, spaceID, reader, PushItemParams{
		ItemID: newTestUUID(), BaseSeq: 0, KeyEpoch: 1, SchemaVer: 1, Blob: "x", Sig: "x",
		Versions: oneVersion(newTestUUID()),
	}); !errors.Is(err, ErrSpaceForbidden) {
		t.Fatalf("reader push: want forbidden, got %v", err)
	}

	// Epoch enforcement: rotate, then a push with the old epoch is rejected.
	if _, err := spaces.Rotate(ctx, spaceID, owner, RotateParams{
		ExpectedEpoch: 1,
		Rewrapped: []MemberWrap{
			{UserID: owner, WrappedKey: "wo2", Signature: "so2"},
			{UserID: reader, WrappedKey: "wr2", Signature: "sr2"},
		},
	}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	outcome, err = spaces.PushItem(ctx, spaceID, owner, PushItemParams{
		ItemID: itemID, BaseSeq: 2, KeyEpoch: 1, SchemaVer: 1, Blob: "old", Sig: "s",
		Versions: oneVersion(newTestUUID()),
	})
	if !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("old epoch push: want stale, got %v", err)
	}
	if outcome.CurrentEpoch != 2 {
		t.Fatalf("stale outcome must carry current epoch 2, got %d", outcome.CurrentEpoch)
	}

	// Stale-epoch pull filter sees the epoch-1 row.
	stale, err := spaces.PullItems(ctx, spaceID, owner, 0, 10, true)
	if err != nil {
		t.Fatalf("stale pull: %v", err)
	}
	if len(stale.Items) != 1 || stale.Items[0].ID != itemID {
		t.Fatalf("stale filter: want the epoch-1 item, got %+v", stale.Items)
	}

	// Tombstone drops the ciphertext and carries no version.
	tombstoned, err := spaces.PushItem(ctx, spaceID, owner, PushItemParams{
		ItemID: itemID, BaseSeq: 2, KeyEpoch: 2, SchemaVer: 1, Deleted: true, Blob: "ignored", Sig: "sd",
	})
	if err != nil {
		t.Fatalf("tombstone: %v", err)
	}
	got, err := spaces.GetItem(ctx, spaceID, owner, itemID)
	if err != nil {
		t.Fatalf("get tombstone: %v", err)
	}
	if !got.Deleted || got.Blob != nil {
		t.Fatalf("tombstone must null blob: %+v", got)
	}
	if tombstoned.Seq != 3 {
		t.Fatalf("tombstone seq: want 3, got %d", tombstoned.Seq)
	}

	// Pull pagination.
	for i := 0; i < 3; i++ {
		id := newTestUUID()
		if _, err := spaces.PushItem(ctx, spaceID, owner, PushItemParams{
			ItemID: id, BaseSeq: 0, KeyEpoch: 2, SchemaVer: 1, Blob: "ct", Sig: "s",
			Versions: oneVersion(newTestUUID()),
		}); err != nil {
			t.Fatalf("page item %d: %v", i, err)
		}
	}
	pageOne, err := spaces.PullItems(ctx, spaceID, owner, 0, 2, false)
	if err != nil {
		t.Fatalf("pull page 1: %v", err)
	}
	if len(pageOne.Items) != 2 || !pageOne.HasMore {
		t.Fatalf("page 1 wrong: items=%d hasMore=%v", len(pageOne.Items), pageOne.HasMore)
	}
	pageTwo, err := spaces.PullItems(ctx, spaceID, owner, pageOne.NextSince, 10, false)
	if err != nil {
		t.Fatalf("pull page 2: %v", err)
	}
	if len(pageTwo.Items) != 2 || pageTwo.HasMore {
		t.Fatalf("page 2 wrong: items=%d hasMore=%v", len(pageTwo.Items), pageTwo.HasMore)
	}

	// Purge: age the tombstone, purge, then a stale cursor gets ErrCursorPurged.
	refs, err := itemRefsFor(spaceID, itemID, nil)
	if err != nil {
		t.Fatalf("item refs: %v", err)
	}
	mustQuery(t, root,
		"UPDATE item SET deleted_at = time::now() - 100d WHERE id = $item",
		map[string]any{"item": refs.item})
	purged, err := spaces.PurgeTombstones(ctx, 90*24*time.Hour)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if purged < 1 {
		t.Fatalf("want >=1 purged, got %d", purged)
	}

	// Delete-forever takes the history with it.
	if remaining := countItemVersions(t, root, spaceID, itemID); remaining != 0 {
		t.Fatalf("purge must delete version rows, %d left", remaining)
	}

	if _, err := spaces.PullItems(ctx, spaceID, owner, 0, 10, false); !errors.Is(err, ErrCursorPurged) {
		t.Fatalf("cursor below horizon: want ErrCursorPurged, got %v", err)
	}
	if _, err := spaces.PullItems(ctx, spaceID, owner, 3, 10, false); err != nil {
		t.Fatalf("cursor at horizon must still work: %v", err)
	}
}

// TestItemIDsAreScopedToTheirSpace asserts the property that replaced the old
// cross-space hijack guard. Item ids used to be global (`contact:<uuid>`), so
// writing a known id from a second space was an attack the push transaction had
// to reject. Now the space is part of the key, so the same uuid in two spaces is
// simply two independent rows — one cannot reach or overwrite the other.
func TestItemIDsAreScopedToTheirSpace(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")

	suffix := randSuffix()
	owner := newSpaceTestUser(t, root, "ci_scope_"+suffix)
	cleanupSpaces(t, root, owner)

	spaces := store.Spaces
	personal, err := spaces.Create(ctx, owner, CreateSpaceParams{
		SpaceID:    newTestUUID(),
		Collection: "contacts", Kind: "personal", WrappedKey: "w", Signature: "s",
	})
	if err != nil {
		t.Fatalf("create personal: %v", err)
	}
	shared, err := spaces.Create(ctx, owner, CreateSpaceParams{
		SpaceID:    newTestUUID(),
		Collection: "contacts", Kind: "shared", WrappedKey: "w2", Signature: "s2",
	})
	if err != nil {
		t.Fatalf("create shared: %v", err)
	}
	personalID := spaceRecord(t, personal.Space.ID)
	sharedID := spaceRecord(t, shared.Space.ID)

	itemID := newTestUUID()
	if _, err := spaces.PushItem(ctx, personalID, owner, PushItemParams{
		ItemID: itemID, BaseSeq: 0, KeyEpoch: 1, SchemaVer: 1, Blob: "personal", Sig: "s",
		Versions: oneVersion(newTestUUID()),
	}); err != nil {
		t.Fatalf("push into personal: %v", err)
	}

	// The same uuid in the other space is a create, not an update: base_seq 0 is
	// accepted even though the personal space already holds seq 1 for that uuid.
	if _, err := spaces.PushItem(ctx, sharedID, owner, PushItemParams{
		ItemID: itemID, BaseSeq: 0, KeyEpoch: 1, SchemaVer: 1, Blob: "shared", Sig: "s",
		Versions: oneVersion(newTestUUID()),
	}); err != nil {
		t.Fatalf("push same uuid into shared space: %v", err)
	}

	fromPersonal, err := spaces.GetItem(ctx, personalID, owner, itemID)
	if err != nil {
		t.Fatalf("get from personal: %v", err)
	}
	fromShared, err := spaces.GetItem(ctx, sharedID, owner, itemID)
	if err != nil {
		t.Fatalf("get from shared: %v", err)
	}
	if *fromPersonal.Blob != "personal" || *fromShared.Blob != "shared" {
		t.Fatalf("rows bled across spaces: %q / %q", *fromPersonal.Blob, *fromShared.Blob)
	}
	if fromPersonal.SpaceID == fromShared.SpaceID {
		t.Fatalf("both rows report the same space: %q", fromPersonal.SpaceID)
	}

	// Each space's history holds only its own version.
	personalVersions, err := spaces.ListItemVersions(ctx, personalID, owner, itemID)
	if err != nil {
		t.Fatalf("personal versions: %v", err)
	}
	if len(personalVersions) != 1 {
		t.Fatalf("want 1 version in the personal space, got %d", len(personalVersions))
	}
}

// TestItemMergeWritesBothVersions covers the conflict-merge push: the losing
// branch and the merge result land under one seq, and the head points at the
// merge result — the last entry.
func TestItemMergeWritesBothVersions(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")

	suffix := randSuffix()
	owner := newSpaceTestUser(t, root, "ci_merge_"+suffix)
	cleanupSpaces(t, root, owner)

	spaces := store.Spaces
	membership, err := spaces.Create(ctx, owner, CreateSpaceParams{
		SpaceID:    newTestUUID(),
		Collection: "contacts", Kind: "personal", WrappedKey: "w", Signature: "s",
	})
	if err != nil {
		t.Fatalf("create space: %v", err)
	}
	spaceID := spaceRecord(t, membership.Space.ID)
	itemID := newTestUUID()
	mergeVersion := newTestUUID()

	if _, err := spaces.PushItem(ctx, spaceID, owner, PushItemParams{
		ItemID: itemID, BaseSeq: 0, KeyEpoch: 1, SchemaVer: 1, Blob: "ct1", Sig: "s1",
		Versions: oneVersion(newTestUUID()),
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := spaces.PushItem(ctx, spaceID, owner, PushItemParams{
		ItemID: itemID, BaseSeq: 1, KeyEpoch: 1, SchemaVer: 1, Blob: "merged", Sig: "sm",
		Versions: []PushVersionParams{
			{VersionID: newTestUUID(), Blob: "vb", Sig: "sb"},
			{VersionID: mergeVersion, Blob: "vm", Sig: "sm"},
		},
	}); err != nil {
		t.Fatalf("merge push: %v", err)
	}

	versions, err := spaces.ListItemVersions(ctx, spaceID, owner, itemID)
	if err != nil {
		t.Fatalf("versions: %v", err)
	}
	if len(versions) != 3 {
		t.Fatalf("want 3 versions after create + merge, got %d", len(versions))
	}
	if versions[1].Seq != versions[2].Seq {
		t.Fatalf("merge versions must share one seq: %d vs %d", versions[1].Seq, versions[2].Seq)
	}

	head, err := spaces.GetItem(ctx, spaceID, owner, itemID)
	if err != nil {
		t.Fatalf("get head: %v", err)
	}
	if head.VersionID != mergeVersion {
		t.Fatalf("head must point at the merge result, got %q", head.VersionID)
	}
}

// TestItemSeqConcurrency pushes 10 items concurrently into one space and asserts
// the assigned seqs are a gap-free permutation — the space-row serialization
// point plus retry must never skip or duplicate a seq.
func TestItemSeqConcurrency(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")

	suffix := randSuffix()
	owner := newSpaceTestUser(t, root, "ci_conc_"+suffix)
	cleanupSpaces(t, root, owner)

	membership, err := store.Spaces.Create(ctx, owner, CreateSpaceParams{
		SpaceID:    newTestUUID(),
		Collection: "contacts", Kind: "personal", WrappedKey: "w", Signature: "s",
	})
	if err != nil {
		t.Fatalf("create space: %v", err)
	}
	spaceID := spaceRecord(t, membership.Space.ID)

	const workers = 10
	seqs := make([]int, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			outcome, err := store.Spaces.PushItem(ctx, spaceID, owner, PushItemParams{
				ItemID:  newTestUUID(),
				BaseSeq: 0, KeyEpoch: 1, SchemaVer: 1, Blob: "ct", Sig: "s",
				Versions: oneVersion(newTestUUID()),
			})
			if err != nil {
				errs[i] = err
				return
			}
			seqs[i] = outcome.Seq
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
	}
	sort.Ints(seqs)
	for i, seq := range seqs {
		if seq != i+1 {
			t.Fatalf("seqs not gap-free: %v", seqs)
		}
	}
}

// spaceRecord rebuilds the uuid-keyed record id from a space id the store
// returned as a string.
func spaceRecord(t *testing.T, spaceID string) models.RecordID {
	t.Helper()
	spaceUUID, err := parseUUID(spaceID)
	if err != nil {
		t.Fatalf("space id %q: %v", spaceID, err)
	}
	return models.NewRecordID("space", spaceUUID)
}
