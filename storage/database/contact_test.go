package database

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// oneVersion builds the history entry an ordinary edit appends.
func oneVersion(id string) []PushVersionParams {
	return []PushVersionParams{{VersionID: id, Blob: "v_" + id, Sig: "vs_" + id}}
}

func countContactVersions(t *testing.T, conn *surrealdb.DB, contactID string) int {
	t.Helper()
	results, err := surrealdb.Query[[]struct {
		Count int `json:"count"`
	}](context.Background(), conn,
		"SELECT count() AS count FROM contact_version WHERE contact = $contact GROUP ALL",
		map[string]any{"contact": models.NewRecordID("contact", contactID)},
	)
	if err != nil {
		t.Fatalf("count contact_version: %v", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0].Count
		}
	}
	return 0
}

// TestContactPushPull covers the envelope write path: OCC on base_seq, version
// rows, tombstoning, epoch enforcement, authz roles, cross-space hijack, pull
// paging, and the purge horizon. Requires migrations 053/054.
func TestContactPushPull(t *testing.T) {
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

	contactID := "item_" + suffix

	// Create: base_seq must be 0.
	if _, err := spaces.PushContact(ctx, spaceID, owner, PushContactParams{
		ContactID: contactID, BaseSeq: 7, KeyEpoch: 1, SchemaVer: 1, Blob: "ct1", Sig: "s1",
		Versions: oneVersion("ver1_" + suffix),
	}); !errors.Is(err, ErrSeqConflict) {
		t.Fatalf("create with nonzero base_seq: want conflict, got %v", err)
	}
	created, err := spaces.PushContact(ctx, spaceID, owner, PushContactParams{
		ContactID: contactID, BaseSeq: 0, KeyEpoch: 1, SchemaVer: 1, Blob: "ct1", Sig: "s1",
		Versions: oneVersion("ver1_" + suffix),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Seq != 1 {
		t.Fatalf("first contact seq: want 1, got %d", created.Seq)
	}

	// Update with correct base_seq bumps seq and appends a second version.
	updated, err := spaces.PushContact(ctx, spaceID, owner, PushContactParams{
		ContactID: contactID, BaseSeq: 1, KeyEpoch: 1, SchemaVer: 1, Blob: "ct2", Sig: "s2",
		Versions: oneVersion("ver2_" + suffix),
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Seq != 2 {
		t.Fatalf("update seq: want 2, got %d", updated.Seq)
	}
	versions, err := spaces.ListContactVersions(ctx, spaceID, owner, contactID)
	if err != nil {
		t.Fatalf("versions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("want 2 versions after create+update, got %d", len(versions))
	}
	if versions[0].Seq != 1 || versions[0].VersionID != "ver1_"+suffix {
		t.Fatalf("first version wrong: %+v", versions[0])
	}
	if versions[1].Blob == nil || *versions[1].Blob != "v_ver2_"+suffix {
		t.Fatalf("second version blob wrong: %+v", versions[1])
	}

	// The head points at the newest version.
	head, err := spaces.GetContact(ctx, spaceID, owner, contactID)
	if err != nil {
		t.Fatalf("get head: %v", err)
	}
	if head.VersionID != "ver2_"+suffix {
		t.Fatalf("head version: want ver2_%s, got %q", suffix, head.VersionID)
	}

	// Stale base_seq conflicts and returns the current row.
	outcome, err := spaces.PushContact(ctx, spaceID, owner, PushContactParams{
		ContactID: contactID, BaseSeq: 1, KeyEpoch: 1, SchemaVer: 1, Blob: "ct3", Sig: "s3",
		Versions: oneVersion("ver3_" + suffix),
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
	if _, err := spaces.PushContact(ctx, spaceID, reader, PushContactParams{
		ContactID: "reader_item_" + suffix, BaseSeq: 0, KeyEpoch: 1, SchemaVer: 1, Blob: "x", Sig: "x",
		Versions: oneVersion("verR_" + suffix),
	}); !errors.Is(err, ErrSpaceForbidden) {
		t.Fatalf("reader push: want forbidden, got %v", err)
	}

	// Cross-space hijack: same contact id via another space is forbidden.
	other, err := spaces.Create(ctx, owner, CreateSpaceParams{
		SpaceID:    "spO_" + suffix,
		Collection: "contacts", Kind: "shared", WrappedKey: "w2", Signature: "s2",
	})
	if err != nil {
		t.Fatalf("create other space: %v", err)
	}
	otherID := models.NewRecordID("space", other.Space.ID)
	if _, err := spaces.PushContact(ctx, otherID, owner, PushContactParams{
		ContactID: contactID, BaseSeq: 2, KeyEpoch: 1, SchemaVer: 1, Blob: "hijack", Sig: "s",
		Versions: oneVersion("verH_" + suffix),
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
	outcome, err = spaces.PushContact(ctx, spaceID, owner, PushContactParams{
		ContactID: contactID, BaseSeq: 2, KeyEpoch: 1, SchemaVer: 1, Blob: "old", Sig: "s",
		Versions: oneVersion("verO_" + suffix),
	})
	if !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("old epoch push: want stale, got %v", err)
	}
	if outcome.CurrentEpoch != 2 {
		t.Fatalf("stale outcome must carry current epoch 2, got %d", outcome.CurrentEpoch)
	}

	// Stale-epoch pull filter sees the epoch-1 row.
	stale, err := spaces.PullContacts(ctx, spaceID, owner, 0, 10, true)
	if err != nil {
		t.Fatalf("stale pull: %v", err)
	}
	if len(stale.Items) != 1 || stale.Items[0].ID != contactID {
		t.Fatalf("stale filter: want the epoch-1 contact, got %+v", stale.Items)
	}

	// Tombstone drops the ciphertext and carries no version.
	tombstoned, err := spaces.PushContact(ctx, spaceID, owner, PushContactParams{
		ContactID: contactID, BaseSeq: 2, KeyEpoch: 2, SchemaVer: 1, Deleted: true, Blob: "ignored", Sig: "sd",
	})
	if err != nil {
		t.Fatalf("tombstone: %v", err)
	}
	got, err := spaces.GetContact(ctx, spaceID, owner, contactID)
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
		id := fmt.Sprintf("page_%s_%d", suffix, i)
		if _, err := spaces.PushContact(ctx, spaceID, owner, PushContactParams{
			ContactID: id, BaseSeq: 0, KeyEpoch: 2, SchemaVer: 1, Blob: "ct", Sig: "s",
			Versions: oneVersion("v_" + id),
		}); err != nil {
			t.Fatalf("page contact %d: %v", i, err)
		}
	}
	pageOne, err := spaces.PullContacts(ctx, spaceID, owner, 0, 2, false)
	if err != nil {
		t.Fatalf("pull page 1: %v", err)
	}
	if len(pageOne.Items) != 2 || !pageOne.HasMore {
		t.Fatalf("page 1 wrong: items=%d hasMore=%v", len(pageOne.Items), pageOne.HasMore)
	}
	pageTwo, err := spaces.PullContacts(ctx, spaceID, owner, pageOne.NextSince, 10, false)
	if err != nil {
		t.Fatalf("pull page 2: %v", err)
	}
	if len(pageTwo.Items) != 2 || pageTwo.HasMore {
		t.Fatalf("page 2 wrong: items=%d hasMore=%v", len(pageTwo.Items), pageTwo.HasMore)
	}

	// Purge: age the tombstone, purge, then a stale cursor gets ErrCursorPurged.
	mustQuery(t, root,
		"UPDATE contact SET deleted_at = time::now() - 100d WHERE id = $contact",
		map[string]any{"contact": models.NewRecordID("contact", contactID)})
	purged, err := spaces.PurgeTombstones(ctx, 90*24*time.Hour)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if purged < 1 {
		t.Fatalf("want >=1 purged, got %d", purged)
	}

	// Delete-forever takes the history with it.
	if remaining := countContactVersions(t, root, contactID); remaining != 0 {
		t.Fatalf("purge must delete version rows, %d left", remaining)
	}

	if _, err := spaces.PullContacts(ctx, spaceID, owner, 0, 10, false); !errors.Is(err, ErrCursorPurged) {
		t.Fatalf("cursor below horizon: want ErrCursorPurged, got %v", err)
	}
	if _, err := spaces.PullContacts(ctx, spaceID, owner, 3, 10, false); err != nil {
		t.Fatalf("cursor at horizon must still work: %v", err)
	}
}

// TestContactMergeWritesBothVersions covers the conflict-merge push: the losing
// branch and the merge result land under one seq, and the head points at the
// merge result — the last entry.
func TestContactMergeWritesBothVersions(t *testing.T) {
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
		SpaceID:    "spM_" + suffix,
		Collection: "contacts", Kind: "personal", WrappedKey: "w", Signature: "s",
	})
	if err != nil {
		t.Fatalf("create space: %v", err)
	}
	spaceID := models.NewRecordID("space", membership.Space.ID)
	contactID := "merge_" + suffix

	if _, err := spaces.PushContact(ctx, spaceID, owner, PushContactParams{
		ContactID: contactID, BaseSeq: 0, KeyEpoch: 1, SchemaVer: 1, Blob: "ct1", Sig: "s1",
		Versions: oneVersion("mv1_" + suffix),
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := spaces.PushContact(ctx, spaceID, owner, PushContactParams{
		ContactID: contactID, BaseSeq: 1, KeyEpoch: 1, SchemaVer: 1, Blob: "merged", Sig: "sm",
		Versions: []PushVersionParams{
			{VersionID: "branch_" + suffix, Blob: "vb", Sig: "sb"},
			{VersionID: "merge_v_" + suffix, Blob: "vm", Sig: "sm"},
		},
	}); err != nil {
		t.Fatalf("merge push: %v", err)
	}

	versions, err := spaces.ListContactVersions(ctx, spaceID, owner, contactID)
	if err != nil {
		t.Fatalf("versions: %v", err)
	}
	if len(versions) != 3 {
		t.Fatalf("want 3 versions after create + merge, got %d", len(versions))
	}
	if versions[1].Seq != versions[2].Seq {
		t.Fatalf("merge versions must share one seq: %d vs %d", versions[1].Seq, versions[2].Seq)
	}

	head, err := spaces.GetContact(ctx, spaceID, owner, contactID)
	if err != nil {
		t.Fatalf("get head: %v", err)
	}
	if head.VersionID != "merge_v_"+suffix {
		t.Fatalf("head must point at the merge result, got %q", head.VersionID)
	}
}

// TestContactSeqConcurrency pushes 10 contacts concurrently into one space and
// asserts the assigned seqs are a gap-free permutation — the space-row
// serialization point plus retry must never skip or duplicate a seq.
func TestContactSeqConcurrency(t *testing.T) {
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
			id := fmt.Sprintf("conc_%s_%d", suffix, i)
			outcome, err := store.Spaces.PushContact(ctx, spaceID, owner, PushContactParams{
				ContactID: id,
				BaseSeq:   0, KeyEpoch: 1, SchemaVer: 1, Blob: "ct", Sig: "s",
				Versions: oneVersion("cv_" + id),
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
