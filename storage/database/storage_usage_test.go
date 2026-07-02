package database

import (
	"context"
	"fmt"
	"testing"

	"github.com/neoworks/auth/oauth"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// TestStorageUsageBreakdown exercises the storage breakdown against the live DB:
// total bytes, per-category sums, per-tier open-interval sums, and the
// reconstructed daily history. Skipped if SurrealDB is unreachable.
func TestStorageUsageBreakdown(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")

	suffix := randSuffix()
	ownerID := "storage_usage_owner_" + suffix
	owner := models.NewRecordID("user", ownerID)
	mustQuery(t, root, "CREATE type::record('user', $id) SET first_name = 'U', last_name = 'U', email = $e, password_hash = 'x'",
		map[string]any{"id": ownerID, "e": ownerID + "@test.local"})

	t.Cleanup(func() {
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE billing_storage_period WHERE billed_to = $u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE media WHERE user = $u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE chunk WHERE user = $u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": owner})
	})

	chunk, err := store.CreateChunk(ctx, ownerID, fmt.Sprintf("%064x", 91), 4096, "k/su/"+suffix)
	if err != nil {
		t.Fatalf("create chunk: %v", err)
	}
	_, err = store.CreateMedia(ctx, &CreateMediaParams{
		UserID: ownerID, Filename: "photo.jpg", MimeType: "image/jpeg", Size: 4096,
		ChunkIDs:   []models.RecordID{*chunk.ID},
		Recipients: []oauth.MediaRecipient{{KeyID: ownerID, WrappedDEK: "w"}},
	})
	if err != nil {
		t.Fatalf("create media: %v", err)
	}

	usage, err := store.StorageUsage(ctx, ownerID)
	if err != nil {
		t.Fatalf("StorageUsage error: %v", err)
	}

	t.Logf("total=%d categories=%+v tiers=%+v historyLen=%d lastPoint=%+v",
		usage.TotalBytes, usage.Categories, usage.Tiers, len(usage.History), usage.History[len(usage.History)-1])

	if usage.TotalBytes != 4096 {
		t.Errorf("total bytes = %d, want 4096", usage.TotalBytes)
	}
	var photos int64
	for _, c := range usage.Categories {
		if c.Category == "photos" {
			photos = c.Bytes
		}
	}
	if photos != 4096 {
		t.Errorf("photos bytes = %d, want 4096", photos)
	}
	var hot int64
	for _, tier := range usage.Tiers {
		if tier.Tier == "hot" {
			hot = tier.Bytes
		}
	}
	if hot != 4096 {
		t.Errorf("hot tier bytes = %d, want 4096", hot)
	}
	if last := usage.History[len(usage.History)-1]; last.Bytes != 4096 {
		t.Errorf("history last point bytes = %d, want 4096", last.Bytes)
	}
}
