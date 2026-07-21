package database

import (
	"context"
	"fmt"
	"testing"

	"github.com/neoworks/auth/oauth"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// TestGetFileManifests covers the batch manifest resolver: the owner gets every
// requested manifest with its own wrapper, a grant holder gets only what they're
// granted, and unreadable / unknown ids are omitted rather than erroring.
// Requires the dev SurrealDB; skipped if unreachable.
func TestGetFileManifests(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")

	suffix := randSuffix()
	ownerID := "mm_owner_" + suffix
	recipientID := "mm_rcpt_" + suffix
	for _, id := range []string{ownerID, recipientID} {
		mustQuery(t, root, "CREATE type::record('user', $id) SET first_name = 'U', last_name = 'U', email = $e, password_hash = 'x'",
			map[string]any{"id": id, "e": id + "@test.local"})
	}

	t.Cleanup(func() {
		for _, id := range []string{ownerID, recipientID} {
			u := models.NewRecordID("user", id)
			_, _ = surrealdb.Query[[]any](ctx, root, "DELETE billing_storage_period WHERE billed_to = $u", map[string]any{"u": u})
			_, _ = surrealdb.Query[[]any](ctx, root, "DELETE file_grant WHERE owner = $u OR recipient = $u", map[string]any{"u": u})
			_, _ = surrealdb.Query[[]any](ctx, root, "DELETE file_version WHERE user = $u", map[string]any{"u": u})
			_, _ = surrealdb.Query[[]any](ctx, root, "DELETE file WHERE user = $u", map[string]any{"u": u})
			_, _ = surrealdb.Query[[]any](ctx, root, "DELETE chunk WHERE user = $u", map[string]any{"u": u})
			_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": u})
		}
	})

	// Two owned file objects, each backed by one chunk.
	makeFile := func(n int) string {
		hash := fmt.Sprintf("%064x", n)
		chunk, err := store.CreateChunk(ctx, ownerID, hash, 16, fmt.Sprintf("mm/key/%s/%d", suffix, n))
		if err != nil {
			t.Fatalf("create chunk %d: %v", n, err)
		}
		m, err := store.CreateFile(ctx, &CreateFileParams{
			UserID:     ownerID,
			Filename:   fmt.Sprintf("photo%d.jpg", n),
			MimeType:   "image/jpeg",
			Size:       16,
			ChunkIDs:   []models.RecordID{*chunk.ID},
			Recipients: []oauth.FileRecipient{{KeyID: ownerID, WrappedDEK: "owner-wrap"}},
		})
		if err != nil {
			t.Fatalf("create file %d: %v", n, err)
		}
		return fmt.Sprintf("%v", m.ID.ID)
	}

	idA := makeFile(1)
	idB := makeFile(2)
	unknownID := "mm_missing_" + suffix

	// Owner sees both, plus the unknown id is silently dropped.
	owned, err := store.GetFileManifests(ctx, []string{idA, idB, unknownID}, ownerID)
	if err != nil {
		t.Fatalf("owner GetFileManifests: %v", err)
	}
	if len(owned) != 2 {
		t.Fatalf("owner: want 2 manifests, got %d", len(owned))
	}
	for _, m := range owned {
		if m.WrappedDEK != "owner-wrap" {
			t.Fatalf("owner manifest %s: want owner-wrap, got %q", m.ID, m.WrappedDEK)
		}
		if len(m.Chunks) != 1 {
			t.Fatalf("owner manifest %s: want 1 chunk, got %d", m.ID, len(m.Chunks))
		}
	}

	// Recipient granted only on A: gets A with their own wrapper, never B.
	if err := store.CreateFileShare(ctx, idA, ownerID, recipientID, "rcpt-wrap"); err != nil {
		t.Fatalf("create file share: %v", err)
	}
	got, err := store.GetFileManifests(ctx, []string{idA, idB}, recipientID)
	if err != nil {
		t.Fatalf("recipient GetFileManifests: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("recipient: want 1 manifest, got %d", len(got))
	}
	if got[0].ID != idA || got[0].WrappedDEK != "rcpt-wrap" {
		t.Fatalf("recipient manifest: id=%s wrap=%q (want %s / rcpt-wrap)", got[0].ID, got[0].WrappedDEK, idA)
	}

	// Empty input is a no-op, not an error.
	empty, err := store.GetFileManifests(ctx, nil, ownerID)
	if err != nil {
		t.Fatalf("empty GetFileManifests: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("empty: want 0 manifests, got %d", len(empty))
	}
}
