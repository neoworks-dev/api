package database

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/neoworks/auth/oauth"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// TestMediaSharing covers the envelope-sharing authorization: a media object is
// readable by its owner, by a user granted a share, and by nobody else; the
// manifest returns each reader's own wrapped DEK; and revocation cuts access.
// Requires the dev SurrealDB with migration 023 applied; skipped if unreachable.
func TestMediaSharing(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")

	suffix := randSuffix()
	ownerID := "media_owner_" + suffix
	recipientID := "media_rcpt_" + suffix
	strangerID := "media_strange_" + suffix
	for _, id := range []string{ownerID, recipientID, strangerID} {
		mustQuery(t, root, "CREATE type::record('user', $id) SET first_name = 'U', last_name = 'U', email = $e, password_hash = 'x'",
			map[string]any{"id": id, "e": id + "@test.local"})
	}

	t.Cleanup(func() {
		for _, id := range []string{ownerID, recipientID, strangerID} {
			u := models.NewRecordID("user", id)
			_, _ = surrealdb.Query[[]any](ctx, root, "DELETE billing_storage_period WHERE billed_to = $u", map[string]any{"u": u})
			_, _ = surrealdb.Query[[]any](ctx, root, "DELETE media_grant WHERE owner = $u OR recipient = $u", map[string]any{"u": u})
			_, _ = surrealdb.Query[[]any](ctx, root, "DELETE media_version WHERE user = $u", map[string]any{"u": u})
			_, _ = surrealdb.Query[[]any](ctx, root, "DELETE media WHERE user = $u", map[string]any{"u": u})
			_, _ = surrealdb.Query[[]any](ctx, root, "DELETE chunk WHERE user = $u", map[string]any{"u": u})
			_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": u})
		}
	})

	// An owner-scoped chunk + a media object referencing it, with the owner as the
	// sole initial recipient.
	hash := fmt.Sprintf("%064x", 1)
	otherHash := fmt.Sprintf("%064x", 2)
	chunk, err := store.CreateChunk(ctx, ownerID, hash, 16, "test/key/"+suffix)
	if err != nil {
		t.Fatalf("create chunk: %v", err)
	}
	// A second chunk owned by the owner but NOT part of the media — a grant must
	// never expose it.
	if _, err := store.CreateChunk(ctx, ownerID, otherHash, 16, "test/key2/"+suffix); err != nil {
		t.Fatalf("create other chunk: %v", err)
	}

	media, err := store.CreateMedia(ctx, &CreateMediaParams{
		UserID:     ownerID,
		Filename:   "photo.jpg",
		MimeType:   "image/jpeg",
		Size:       16,
		ChunkIDs:   []models.RecordID{*chunk.ID},
		Recipients: []oauth.MediaRecipient{{KeyID: ownerID, WrappedDEK: "owner-wrap"}},
	})
	if err != nil {
		t.Fatalf("create media: %v", err)
	}
	mediaID := fmt.Sprintf("%v", media.ID.ID)

	// Owner can read its own chunk.
	if _, err := store.GetReadableChunk(ctx, mediaID, hash, ownerID); err != nil {
		t.Fatalf("owner GetReadableChunk: %v", err)
	}
	// Owner cannot pull a chunk that is not part of this media.
	if _, err := store.GetReadableChunk(ctx, mediaID, otherHash, ownerID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("owner reading non-member chunk: want ErrNotFound, got %v", err)
	}
	// Recipient cannot read before a grant exists.
	if _, err := store.GetReadableChunk(ctx, mediaID, hash, recipientID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ungranted recipient: want ErrNotFound, got %v", err)
	}

	// Share with the recipient.
	if err := store.CreateMediaShare(ctx, mediaID, ownerID, recipientID, "rcpt-wrap"); err != nil {
		t.Fatalf("create media share: %v", err)
	}
	// A non-owner cannot share.
	if err := store.CreateMediaShare(ctx, mediaID, strangerID, recipientID, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("non-owner share: want ErrNotFound, got %v", err)
	}

	// Recipient can now read the member chunk, but still not the non-member one.
	if _, err := store.GetReadableChunk(ctx, mediaID, hash, recipientID); err != nil {
		t.Fatalf("granted recipient GetReadableChunk: %v", err)
	}
	if _, err := store.GetReadableChunk(ctx, mediaID, otherHash, recipientID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("recipient reading non-member chunk: want ErrNotFound, got %v", err)
	}
	// A stranger still cannot read.
	if _, err := store.GetReadableChunk(ctx, mediaID, hash, strangerID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stranger GetReadableChunk: want ErrNotFound, got %v", err)
	}

	// Manifest returns each reader's own wrapper.
	ownerManifest, err := store.GetMediaManifest(ctx, mediaID, ownerID)
	if err != nil || ownerManifest.WrappedDEK != "owner-wrap" {
		t.Fatalf("owner manifest wrapper: %q err=%v", safeWrap(ownerManifest), err)
	}
	rcptManifest, err := store.GetMediaManifest(ctx, mediaID, recipientID)
	if err != nil || rcptManifest.WrappedDEK != "rcpt-wrap" {
		t.Fatalf("recipient manifest wrapper: %q err=%v", safeWrap(rcptManifest), err)
	}

	// Revoke: recipient loses both manifest access and chunk reads.
	if err := store.DeleteMediaShare(ctx, mediaID, ownerID, recipientID); err != nil {
		t.Fatalf("delete media share: %v", err)
	}
	if _, err := store.GetReadableChunk(ctx, mediaID, hash, recipientID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked recipient GetReadableChunk: want ErrNotFound, got %v", err)
	}
	if _, err := store.GetMediaManifest(ctx, mediaID, recipientID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked recipient manifest: want ErrNotFound, got %v", err)
	}

	// Billing lifecycle: CreateChunk opened a storage period (end_time NONE);
	// deleting the media GCs the chunk and must close that period.
	if open := countOpenStoragePeriods(t, root, *chunk.ID); open != 1 {
		t.Fatalf("want 1 open billing period for the chunk, got %d", open)
	}
	if _, err := store.DeleteMedia(ctx, mediaID, ownerID); err != nil {
		t.Fatalf("delete media: %v", err)
	}
	if open := countOpenStoragePeriods(t, root, *chunk.ID); open != 0 {
		t.Fatalf("billing period not closed on removal: %d still open", open)
	}
}

// countOpenStoragePeriods returns how many billing_storage_period rows reference
// the chunk and are still open (end_time unset).
func countOpenStoragePeriods(t *testing.T, conn *surrealdb.DB, chunkRef models.RecordID) int {
	t.Helper()
	type row struct {
		EndTime *time.Time `json:"end_time"`
	}
	results, err := surrealdb.Query[[]row](context.Background(), conn,
		"SELECT end_time FROM billing_storage_period WHERE ref = $ref",
		map[string]any{"ref": chunkRef},
	)
	if err != nil {
		t.Fatalf("query billing periods: %v", err)
	}
	open := 0
	for _, qr := range *results {
		for _, r := range qr.Result {
			if r.EndTime == nil {
				open++
			}
		}
	}
	return open
}

func safeWrap(m *MediaManifestData) string {
	if m == nil {
		return "<nil>"
	}
	return m.WrappedDEK
}
