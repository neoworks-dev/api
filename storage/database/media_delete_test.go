package database

import (
	"context"
	"fmt"
	"testing"

	"github.com/neoworks/auth/oauth"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// TestMediaDeleteCascade verifies deleting a photo also deletes its linked
// thumbnail (and both objects' chunks + the embedding queue row). Skipped if
// SurrealDB is unreachable.
func TestMediaDeleteCascade(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")

	suffix := randSuffix()
	ownerID := "media_del_owner_" + suffix
	owner := models.NewRecordID("user", ownerID)
	mustQuery(t, root, "CREATE type::record('user', $id) SET first_name = 'U', last_name = 'U', email = $e, password_hash = 'x'",
		map[string]any{"id": ownerID, "e": ownerID + "@test.local"})

	t.Cleanup(func() {
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE billing_storage_period WHERE billed_to = $u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE media_embedding WHERE user = $u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE media_version WHERE user = $u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE media WHERE user = $u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE chunk WHERE user = $u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": owner})
	})

	thumbChunk, _ := store.CreateChunk(ctx, ownerID, fmt.Sprintf("%064x", 21), 8, "k/t/"+suffix)
	thumbPurpose := "thumbnail"
	thumb, err := store.CreateMedia(ctx, &CreateMediaParams{
		UserID: ownerID, Filename: "p.jpg.thumb.jpg", MimeType: "image/jpeg", Size: 8,
		ChunkIDs:   []models.RecordID{*thumbChunk.ID},
		Recipients: []oauth.MediaRecipient{{KeyID: ownerID, WrappedDEK: "w"}},
		Purpose:    &thumbPurpose,
	})
	if err != nil {
		t.Fatalf("thumb media: %v", err)
	}
	thumbID := fmt.Sprintf("%v", thumb.ID.ID)

	origChunk, _ := store.CreateChunk(ctx, ownerID, fmt.Sprintf("%064x", 22), 16, "k/o/"+suffix)
	orig, err := store.CreateMedia(ctx, &CreateMediaParams{
		UserID: ownerID, Filename: "p.jpg", MimeType: "image/jpeg", Size: 16,
		ChunkIDs:    []models.RecordID{*origChunk.ID},
		Recipients:  []oauth.MediaRecipient{{KeyID: ownerID, WrappedDEK: "w"}},
		ThumbnailID: &thumbID,
	})
	if err != nil {
		t.Fatalf("orig media: %v", err)
	}
	origID := fmt.Sprintf("%v", orig.ID.ID)

	dead, err := store.DeleteMedia(ctx, origID, ownerID)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	// Both chunks are now unreferenced and returned for blob GC.
	if len(dead) != 2 {
		t.Fatalf("dead chunks = %d, want 2 (original + thumbnail)", len(dead))
	}

	// Neither media row, nor either chunk, nor the embedding row survives.
	if n := countRows(t, root, "media", owner); n != 0 {
		t.Fatalf("media rows after delete = %d, want 0", n)
	}
	if n := countRows(t, root, "chunk", owner); n != 0 {
		t.Fatalf("chunk rows after delete = %d, want 0", n)
	}
	if n := countRows(t, root, "media_embedding", owner); n != 0 {
		t.Fatalf("media_embedding rows after delete = %d, want 0", n)
	}
}

func countRows(t *testing.T, conn *surrealdb.DB, table string, owner models.RecordID) int {
	t.Helper()
	results, err := surrealdb.Query[[]struct {
		Count int `json:"count"`
	}](context.Background(), conn,
		fmt.Sprintf("SELECT count() AS count FROM %s WHERE user = $u GROUP ALL", table),
		map[string]any{"u": owner},
	)
	if err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0].Count
		}
	}
	return 0
}
