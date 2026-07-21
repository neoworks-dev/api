package database

import (
	"context"
	"fmt"
	"testing"

	gql_model "github.com/neoworks/auth/gql/model"
	"github.com/neoworks/auth/oauth"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// TestFileListAndSearch exercises the queryable surface against the live DB: the
// embedding_status subquery, thumbnail linkage + exclusion, the pending-embedding
// queue, the 768-dim cosine arm, and the filename BM25 arm. Skipped if SurrealDB
// is unreachable; requires migrations 025–028.
func TestFileListAndSearch(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")

	suffix := randSuffix()
	ownerID := "file_list_owner_" + suffix
	owner := models.NewRecordID("user", ownerID)
	mustQuery(t, root, "CREATE type::record('user', $id) SET first_name = 'U', last_name = 'U', email = $e, password_hash = 'x'",
		map[string]any{"id": ownerID, "e": ownerID + "@test.local"})

	t.Cleanup(func() {
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE billing_storage_period WHERE billed_to = $u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE file_embedding WHERE user = $u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE file_version WHERE user = $u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE file WHERE user = $u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE chunk WHERE user = $u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": owner})
	})

	// A thumbnail file (purpose=thumbnail) and the original linking to it.
	thumbChunk, err := store.CreateChunk(ctx, ownerID, fmt.Sprintf("%064x", 11), 8, "k/thumb/"+suffix)
	if err != nil {
		t.Fatalf("thumb chunk: %v", err)
	}
	thumbPurpose := "thumbnail"
	thumb, err := store.CreateFile(ctx, &CreateFileParams{
		UserID: ownerID, Filename: "beach.jpg.thumb.jpg", MimeType: "image/jpeg", Size: 8,
		ChunkIDs:   []models.RecordID{*thumbChunk.ID},
		Recipients: []oauth.FileRecipient{{KeyID: ownerID, WrappedDEK: "w"}},
		Purpose:    &thumbPurpose,
	})
	if err != nil {
		t.Fatalf("create thumb file: %v", err)
	}
	thumbID := fmt.Sprintf("%v", thumb.ID.ID)

	origChunk, err := store.CreateChunk(ctx, ownerID, fmt.Sprintf("%064x", 12), 16, "k/orig/"+suffix)
	if err != nil {
		t.Fatalf("orig chunk: %v", err)
	}
	orig, err := store.CreateFile(ctx, &CreateFileParams{
		UserID: ownerID, Filename: "beach-sunset.jpg", MimeType: "image/jpeg", Size: 16,
		ChunkIDs:    []models.RecordID{*origChunk.ID},
		Recipients:  []oauth.FileRecipient{{KeyID: ownerID, WrappedDEK: "w"}},
		ThumbnailID: &thumbID,
	})
	if err != nil {
		t.Fatalf("create orig file: %v", err)
	}
	origID := fmt.Sprintf("%v", orig.ID.ID)

	// List excludes the thumbnail, projects the thumbnail link + pending status.
	items, err := store.ListFileQuery(ctx, owner, false, nil, nil, 50, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(items) != 1 || items[0].ID != origID {
		t.Fatalf("list = %d items, want only the original", len(items))
	}
	if items[0].ThumbnailID == nil || *items[0].ThumbnailID != thumbID {
		t.Fatalf("thumbnailId = %v, want %s", items[0].ThumbnailID, thumbID)
	}
	if items[0].EmbeddingStatus == nil || *items[0].EmbeddingStatus != "pending" {
		t.Fatalf("embeddingStatus = %v, want pending", items[0].EmbeddingStatus)
	}

	if n, err := store.CountFileQuery(ctx, owner, false, nil); err != nil || n != 1 {
		t.Fatalf("count = %d (err %v), want 1", n, err)
	}

	// Sorting by capture date must run against the live DB: the column maps to the
	// coalesced "(capture_date OR created_at)" expression so EXIF-less photos fall
	// back to their upload time instead of sinking to the bottom.
	descDir := gql_model.SortDirectionDesc
	sorted, err := store.ListFileQuery(ctx, owner, false, nil,
		[]*gql_model.FileSort{{Field: gql_model.FileSortFieldCaptureDate, Direction: &descDir}}, 50, 0)
	if err != nil {
		t.Fatalf("sorted list: %v", err)
	}
	if len(sorted) != 1 || sorted[0].ID != origID {
		t.Fatalf("sorted list = %v, want the original", sorted)
	}

	// The thumbnail must not have been queued for embedding; only the original.
	pending, err := store.ListPendingFileEmbeddings(ctx, owner, 50)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(pending) != 1 || pending[0].FileID != origID {
		t.Fatalf("pending = %v, want only the original", pending)
	}

	// Fill the embedding, then it should read ready and the queue should drain.
	vec := make([]float32, 768)
	for i := range vec {
		vec[i] = 0.03
	}
	if err := store.SetFileEmbedding(ctx, &SetFileEmbeddingParams{
		FileID: origID, UserID: ownerID, Modality: "image",
		Model: "nomic-embed-vision-v1.5", Dim: 768, Vector: vec,
	}); err != nil {
		t.Fatalf("set embedding: %v", err)
	}
	if pending, _ := store.ListPendingFileEmbeddings(ctx, owner, 50); len(pending) != 0 {
		t.Fatalf("pending after fill = %d, want 0", len(pending))
	}
	items, _ = store.ListFileQuery(ctx, owner, false, nil, nil, 50, 0)
	if len(items) != 1 || items[0].EmbeddingStatus == nil || *items[0].EmbeddingStatus != "ready" {
		t.Fatalf("embeddingStatus after fill = %v, want ready", items[0].EmbeddingStatus)
	}

	// Vector arm (cosine) finds the original.
	hits, err := store.SearchFile(ctx, owner, vec, "", 10)
	if err != nil {
		t.Fatalf("vector search: %v", err)
	}
	if len(hits) != 1 || hits[0].ID != origID {
		t.Fatalf("vector search = %v, want the original", hits)
	}

	// Lexical arm (filename BM25) finds the original and never the thumbnail.
	hits, err = store.SearchFile(ctx, owner, nil, "sunset", 10)
	if err != nil {
		t.Fatalf("lexical search: %v", err)
	}
	if len(hits) != 1 || hits[0].ID != origID {
		t.Fatalf("lexical search = %v, want the original", hits)
	}

	// A filter compiles + runs end-to-end.
	filtered, err := store.ListFileQuery(ctx, owner, false,
		&gql_model.FileFilter{MimeType: &gql_model.StringFilter{StartsWith: strptr("image/")}},
		[]*gql_model.FileSort{{Field: gql_model.FileSortFieldCreatedAt}}, 50, 0)
	if err != nil || len(filtered) != 1 {
		t.Fatalf("filtered list = %d (err %v), want 1", len(filtered), err)
	}
}
