package database

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// TestContactItemPushPull covers the envelope write path: OCC on base_seq,
// version-row copies, tombstoning, epoch enforcement, authz roles, cross-space
// hijack, pull paging, and the purge horizon. Requires migrations 053/054.
func TestContactItemPushPull(t *testing.T) {
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
		SpaceID:    "sp_" + suffix,
		Collection: "contacts", Kind: "personal", WrappedKey: "wrap", Signature: "sig",
	})
	if err != nil {
		t.Fatalf("create space: %v", err)
	}
	spaceID := models.NewRecordID("space", membership.Space.ID)

	itemID := "item_" + suffix

	// Create: base_seq must be 0.
	if _, err := spaces.PushItem(ctx, spaceID, owner, PushItemParams{
		ItemID: itemID, BaseSeq: 7, KeyEpoch: 1, SchemaVer: 1, Blob: "ct1", Sig: "s1",
	}); !errors.Is(err, ErrSeqConflict) {
		t.Fatalf("create with nonzero base_seq: want conflict, got %v", err)
	}
	created, err := spaces.PushItem(ctx, spaceID, owner, PushItemParams{
		ItemID: itemID, BaseSeq: 0, KeyEpoch: 1, SchemaVer: 1, Blob: "ct1", Sig: "s1",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Seq != 1 {
		t.Fatalf("first item seq: want 1, got %d", created.Seq)
	}

	// Update with correct base_seq bumps seq and archives a version row.
	updated, err := spaces.PushItem(ctx, spaceID, owner, PushItemParams{
		ItemID: itemID, BaseSeq: 1, KeyEpoch: 1, SchemaVer: 1, Blob: "ct2", Sig: "s2",
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
	if len(versions) != 1 || versions[0].Seq != 1 || versions[0].Blob == nil || *versions[0].Blob != "ct1" {
		t.Fatalf("version row wrong: %+v", versions)
	}

	// Stale base_seq conflicts and returns the current row.
	outcome, err := spaces.PushItem(ctx, spaceID, owner, PushItemParams{
		ItemID: itemID, BaseSeq: 1, KeyEpoch: 1, SchemaVer: 1, Blob: "ct3", Sig: "s3",
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
		ItemID: "reader_item_" + suffix, BaseSeq: 0, KeyEpoch: 1, SchemaVer: 1, Blob: "x", Sig: "x",
	}); !errors.Is(err, ErrSpaceForbidden) {
		t.Fatalf("reader push: want forbidden, got %v", err)
	}

	// Cross-space hijack: same item id via another space is forbidden.
	other, err := spaces.Create(ctx, owner, CreateSpaceParams{
		SpaceID:    "spO_" + suffix,
		Collection: "contacts", Kind: "shared", WrappedKey: "w2", Signature: "s2",
	})
	if err != nil {
		t.Fatalf("create other space: %v", err)
	}
	otherID := models.NewRecordID("space", other.Space.ID)
	if _, err := spaces.PushItem(ctx, otherID, owner, PushItemParams{
		ItemID: itemID, BaseSeq: 2, KeyEpoch: 1, SchemaVer: 1, Blob: "hijack", Sig: "s",
	}); !errors.Is(err, ErrSpaceForbidden) {
		t.Fatalf("cross-space hijack: want forbidden, got %v", err)
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

	// Tombstone drops the ciphertext.
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
		if _, err := spaces.PushItem(ctx, spaceID, owner, PushItemParams{
			ItemID: fmt.Sprintf("page_%s_%d", suffix, i), BaseSeq: 0, KeyEpoch: 2, SchemaVer: 1,
			Blob: "ct", Sig: "s",
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
	mustQuery(t, root,
		"UPDATE contact_item SET deleted_at = time::now() - 100d WHERE id = $item",
		map[string]any{"item": models.NewRecordID("contact_item", itemID)})
	purged, err := spaces.PurgeTombstones(ctx, 90*24*time.Hour)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if purged < 1 {
		t.Fatalf("want >=1 purged, got %d", purged)
	}
	if _, err := spaces.PullItems(ctx, spaceID, owner, 0, 10, false); !errors.Is(err, ErrCursorPurged) {
		t.Fatalf("cursor below horizon: want ErrCursorPurged, got %v", err)
	}
	if _, err := spaces.PullItems(ctx, spaceID, owner, 3, 10, false); err != nil {
		t.Fatalf("cursor at horizon must still work: %v", err)
	}
}

// TestContactItemSeqConcurrency pushes 10 items concurrently into one space and
// asserts the assigned seqs are a gap-free permutation — the space-row
// serialization point plus retry must never skip or duplicate a seq.
func TestContactItemSeqConcurrency(t *testing.T) {
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
		SpaceID:    "spC_" + suffix,
		Collection: "contacts", Kind: "personal", WrappedKey: "w", Signature: "s",
	})
	if err != nil {
		t.Fatalf("create space: %v", err)
	}
	spaceID := models.NewRecordID("space", membership.Space.ID)

	const workers = 10
	seqs := make([]int, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			outcome, err := store.Spaces.PushItem(ctx, spaceID, owner, PushItemParams{
				ItemID:  fmt.Sprintf("conc_%s_%d", suffix, i),
				BaseSeq: 0, KeyEpoch: 1, SchemaVer: 1, Blob: "ct", Sig: "s",
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
