package database

import (
	"context"
	"errors"
	"testing"

	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// newSpaceTestUser creates a bare user row and returns its RecordID.
func newSpaceTestUser(t *testing.T, root *surrealdb.DB, id string) models.RecordID {
	t.Helper()
	mustQuery(t, root,
		"CREATE type::record('user', $id) SET first_name = 'S', last_name = 'S', email = $e, password_hash = 'x'",
		map[string]any{"id": id, "e": id + "@test.local"})
	return models.NewRecordID("user", id)
}

func cleanupSpaces(t *testing.T, root *surrealdb.DB, userIDs ...models.RecordID) {
	t.Helper()
	ctx := context.Background()
	t.Cleanup(func() {
		for _, u := range userIDs {
			_, _ = surrealdb.Query[[]any](ctx, root, "DELETE contact_item_version WHERE space.owner = $u", map[string]any{"u": u})
			_, _ = surrealdb.Query[[]any](ctx, root, "DELETE contact_item WHERE space.owner = $u", map[string]any{"u": u})
			_, _ = surrealdb.Query[[]any](ctx, root, "DELETE space_member WHERE space.owner = $u", map[string]any{"u": u})
			_, _ = surrealdb.Query[[]any](ctx, root, "DELETE space WHERE owner = $u", map[string]any{"u": u})
			_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": u})
		}
	})
}

// TestSpaceLifecycle covers create (personal idempotency), invite/accept,
// wrap-coverage validation, removal, and epoch rotation with its concurrency
// assert. Requires the dev SurrealDB with migrations 053+ applied.
func TestSpaceLifecycle(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")

	suffix := randSuffix()
	owner := newSpaceTestUser(t, root, "space_owner_"+suffix)
	partner := newSpaceTestUser(t, root, "space_partner_"+suffix)
	cleanupSpaces(t, root, owner, partner)

	spaces := store.Spaces

	// Personal space create is idempotent per (owner, collection).
	first, err := spaces.Create(ctx, owner, CreateSpaceParams{
		SpaceID:    "sp1_" + suffix,
		Collection: "contacts", Kind: "personal", WrappedKey: "wrap1", Signature: "sig1",
	})
	if err != nil {
		t.Fatalf("create personal: %v", err)
	}
	second, err := spaces.Create(ctx, owner, CreateSpaceParams{
		SpaceID:    "sp2_" + suffix,
		Collection: "contacts", Kind: "personal", WrappedKey: "other", Signature: "other",
	})
	if err != nil {
		t.Fatalf("create personal again: %v", err)
	}
	if first.Space.ID != second.Space.ID {
		t.Fatalf("personal create not idempotent: %s vs %s", first.Space.ID, second.Space.ID)
	}
	if first.Member.Role != "owner" || first.Member.Status != "active" {
		t.Fatalf("owner membership wrong: %+v", first.Member)
	}

	// Shared space + invite flow.
	shared, err := spaces.Create(ctx, owner, CreateSpaceParams{
		SpaceID:    "spS_" + suffix,
		Collection: "contacts", Kind: "shared", WrappedKey: "wrapS", Signature: "sigS",
	})
	if err != nil {
		t.Fatalf("create shared: %v", err)
	}
	sharedID := models.NewRecordID("space", shared.Space.ID)

	// Invite must cover all live epochs (currently just epoch 1).
	if _, err := spaces.InviteMember(ctx, sharedID, owner, InviteParams{
		MemberID: partner, Role: "writer",
		WrappedKeys: []WrappedKey{{Epoch: 99, WrappedKey: "w", Signature: "s"}},
	}); err == nil {
		t.Fatal("invite with wrong epoch coverage must fail")
	}
	if _, err := spaces.InviteMember(ctx, sharedID, owner, InviteParams{
		MemberID: partner, Role: "writer",
		WrappedKeys: []WrappedKey{{Epoch: 1, WrappedKey: "wrapP", Signature: "sigP"}},
	}); err != nil {
		t.Fatalf("invite: %v", err)
	}

	// Invited member cannot pull until accepting.
	if _, err := spaces.PullItems(ctx, sharedID, partner, 0, 10, false); !errors.Is(err, ErrSpaceForbidden) {
		t.Fatalf("invited member pull: want forbidden, got %v", err)
	}
	if err := spaces.Accept(ctx, sharedID, partner, "acceptSig"); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := spaces.PullItems(ctx, sharedID, partner, 0, 10, false); err != nil {
		t.Fatalf("active member pull: %v", err)
	}

	// ListForUser returns both memberships for the owner.
	memberships, err := spaces.ListForUser(ctx, owner, "contacts")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(memberships) != 2 {
		t.Fatalf("want 2 memberships, got %d", len(memberships))
	}

	// Get redacts other members' wrapped keys.
	detail, err := spaces.Get(ctx, sharedID, partner)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	for _, m := range detail.Members {
		ownRow := m.UserID == partner.ID.(string)
		if ownRow && len(m.WrappedKeys) == 0 {
			t.Fatal("caller's own wrapped keys missing")
		}
		if !ownRow && len(m.WrappedKeys) != 0 {
			t.Fatal("other member's wrapped keys leaked")
		}
	}

	// Rotation: wrong expected epoch loses; correct one bumps and appends wraps.
	rewrapsAll := []MemberWrap{
		{UserID: owner, WrappedKey: "wrapO2", Signature: "sigO2"},
		{UserID: partner, WrappedKey: "wrapP2", Signature: "sigP2"},
	}
	if _, err := spaces.Rotate(ctx, sharedID, owner, RotateParams{
		ExpectedEpoch: 42, Rewrapped: rewrapsAll,
	}); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("rotate stale epoch: want ErrStaleEpoch, got %v", err)
	}
	if _, err := spaces.Rotate(ctx, sharedID, owner, RotateParams{
		ExpectedEpoch: 1, Rewrapped: rewrapsAll[:1],
	}); err == nil {
		t.Fatal("rotate with incomplete member coverage must fail")
	}
	newEpoch, err := spaces.Rotate(ctx, sharedID, owner, RotateParams{
		ExpectedEpoch: 1, Rewrapped: rewrapsAll,
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if newEpoch != 2 {
		t.Fatalf("want epoch 2, got %d", newEpoch)
	}
	afterRotate, err := spaces.Get(ctx, sharedID, partner)
	if err != nil {
		t.Fatalf("get after rotate: %v", err)
	}
	if afterRotate.Space.KeyEpoch != 2 {
		t.Fatalf("space epoch not bumped: %d", afterRotate.Space.KeyEpoch)
	}
	for _, m := range afterRotate.Members {
		if m.UserID != partner.ID.(string) {
			continue
		}
		if len(m.WrappedKeys) != 2 {
			t.Fatalf("partner should hold 2 epoch wraps, got %d", len(m.WrappedKeys))
		}
	}

	// Removal: partner is out, pull dies; owner cannot be removed.
	if _, err := spaces.RemoveMember(ctx, sharedID, owner, owner); err == nil {
		t.Fatal("removing the owner must fail")
	}
	epoch, err := spaces.RemoveMember(ctx, sharedID, owner, partner)
	if err != nil {
		t.Fatalf("remove member: %v", err)
	}
	if epoch != 2 {
		t.Fatalf("remove should report current epoch 2, got %d", epoch)
	}
	if _, err := spaces.PullItems(ctx, sharedID, partner, 0, 10, false); !errors.Is(err, ErrSpaceForbidden) {
		t.Fatalf("removed member pull: want forbidden, got %v", err)
	}

	// Personal spaces cannot be deleted; shared ones can.
	personalID := models.NewRecordID("space", first.Space.ID)
	if err := spaces.Delete(ctx, personalID, owner); err == nil {
		t.Fatal("deleting personal space must fail")
	}
	if err := spaces.Delete(ctx, sharedID, owner); err != nil {
		t.Fatalf("delete shared space: %v", err)
	}
	if _, err := spaces.Get(ctx, sharedID, owner); !errors.Is(err, ErrSpaceForbidden) && !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted space still readable: %v", err)
	}
}
