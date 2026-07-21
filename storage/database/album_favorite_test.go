package database

import (
	"context"
	"fmt"
	"testing"

	"github.com/neoworks/auth/oauth"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// TestAlbumsAndFavorites exercises the album + favorite stores end to end: the
// favorite flag/listing, album create/add/cover/count/remove, and the delete
// cascade that drops a file's favorite + album membership rows. Skipped if
// SurrealDB is unreachable.
func TestAlbumsAndFavorites(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")

	suffix := randSuffix()
	ownerID := "album_owner_" + suffix
	owner := models.NewRecordID("user", ownerID)
	mustQuery(t, root, "CREATE type::record('user', $id) SET first_name = 'U', last_name = 'U', email = $e, password_hash = 'x'",
		map[string]any{"id": ownerID, "e": ownerID + "@test.local"})

	t.Cleanup(func() {
		for _, table := range []string{"album_file", "album", "file_favorite", "file_embedding", "file_version", "file", "chunk"} {
			_, _ = surrealdb.Query[[]any](ctx, root, "DELETE "+table+" WHERE user = $u", map[string]any{"u": owner})
		}
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": owner})
	})

	// A file with a linked thumbnail (the album cover is derived from it).
	thumbChunk, _ := store.CreateChunk(ctx, ownerID, fmt.Sprintf("%064x", 31), 8, "k/at/"+suffix)
	thumbPurpose := "thumbnail"
	thumb, err := store.CreateFile(ctx, &CreateFileParams{
		UserID: ownerID, Filename: "a.jpg.thumb.jpg", MimeType: "image/jpeg", Size: 8,
		ChunkIDs:   []models.RecordID{*thumbChunk.ID},
		Recipients: []oauth.FileRecipient{{KeyID: ownerID, WrappedDEK: "w"}},
		Purpose:    &thumbPurpose,
	})
	if err != nil {
		t.Fatalf("thumb file: %v", err)
	}
	thumbID := fmt.Sprintf("%v", thumb.ID.ID)

	origChunk, _ := store.CreateChunk(ctx, ownerID, fmt.Sprintf("%064x", 32), 16, "k/ao/"+suffix)
	orig, err := store.CreateFile(ctx, &CreateFileParams{
		UserID: ownerID, Filename: "a.jpg", MimeType: "image/jpeg", Size: 16,
		ChunkIDs:    []models.RecordID{*origChunk.ID},
		Recipients:  []oauth.FileRecipient{{KeyID: ownerID, WrappedDEK: "w"}},
		ThumbnailID: &thumbID,
	})
	if err != nil {
		t.Fatalf("orig file: %v", err)
	}
	origID := fmt.Sprintf("%v", orig.ID.ID)
	fileRec := models.NewRecordID("file", origID)

	// ── Favorites ─────────────────────────────────────────────────────────────
	fav, err := store.SetFileFavorite(ctx, fileRec, owner, true)
	if err != nil {
		t.Fatalf("favorite: %v", err)
	}
	if !fav.Favorite {
		t.Fatal("file.favorite = false after favoriting")
	}
	if items, err := store.ListFavoriteFile(ctx, owner, nil, 50, 0); err != nil || len(items) != 1 {
		t.Fatalf("favorites listing = %d (err %v), want 1", len(items), err)
	}

	unfav, err := store.SetFileFavorite(ctx, fileRec, owner, false)
	if err != nil || unfav.Favorite {
		t.Fatalf("unfavorite: favorite=%v err=%v", unfav.Favorite, err)
	}
	if items, _ := store.ListFavoriteFile(ctx, owner, nil, 50, 0); len(items) != 0 {
		t.Fatalf("favorites after unfavorite = %d, want 0", len(items))
	}

	// ── Albums ────────────────────────────────────────────────────────────────
	album, err := store.Albums.CreateAlbum(ctx, owner, "Trip")
	if err != nil {
		t.Fatalf("create album: %v", err)
	}
	if album.Count != 0 || album.CoverThumbnailID != nil {
		t.Fatalf("fresh album: count=%d cover=%v, want 0/nil", album.Count, album.CoverThumbnailID)
	}
	albumRec := models.NewRecordID("album", album.ID)

	added, err := store.Albums.AddFileToAlbum(ctx, albumRec, owner, []models.RecordID{fileRec})
	if err != nil {
		t.Fatalf("add to album: %v", err)
	}
	if added.Count != 1 {
		t.Fatalf("album count after add = %d, want 1", added.Count)
	}
	if added.CoverThumbnailID == nil || *added.CoverThumbnailID != thumbID {
		t.Fatalf("album cover = %v, want %s", added.CoverThumbnailID, thumbID)
	}
	if items, err := store.ListAlbumFile(ctx, albumRec, owner, nil, 50, 0); err != nil || len(items) != 1 {
		t.Fatalf("album file = %d (err %v), want 1", len(items), err)
	}

	// Idempotent re-add keeps the count at 1.
	if reAdded, _ := store.Albums.AddFileToAlbum(ctx, albumRec, owner, []models.RecordID{fileRec}); reAdded.Count != 1 {
		t.Fatalf("album count after re-add = %d, want 1", reAdded.Count)
	}

	removed, err := store.Albums.RemoveFileFromAlbum(ctx, albumRec, owner, []models.RecordID{fileRec})
	if err != nil || removed.Count != 0 {
		t.Fatalf("remove from album: count=%d err=%v", removed.Count, err)
	}

	// ── Rename ────────────────────────────────────────────────────────────────
	if renamed, err := store.Albums.RenameAlbum(ctx, albumRec, owner, "Vacation"); err != nil || renamed.Name != "Vacation" {
		t.Fatalf("rename: name=%q err=%v", renamed.Name, err)
	}

	// ── Delete cascade ────────────────────────────────────────────────────────
	// Re-add + favorite, then delete the file: both edge rows must vanish.
	if _, err := store.Albums.AddFileToAlbum(ctx, albumRec, owner, []models.RecordID{fileRec}); err != nil {
		t.Fatalf("re-add for cascade: %v", err)
	}
	if _, err := store.SetFileFavorite(ctx, fileRec, owner, true); err != nil {
		t.Fatalf("re-favorite for cascade: %v", err)
	}
	if _, err := store.DeleteFile(ctx, origID, ownerID); err != nil {
		t.Fatalf("delete file: %v", err)
	}
	if n := countRows(t, root, "file_favorite", owner); n != 0 {
		t.Fatalf("file_favorite after file delete = %d, want 0", n)
	}
	if n := countRows(t, root, "album_file", owner); n != 0 {
		t.Fatalf("album_file after file delete = %d, want 0", n)
	}
	if reloaded, _ := store.Albums.GetAlbum(ctx, albumRec, owner); reloaded == nil || reloaded.Count != 0 {
		t.Fatalf("album after member delete: %v", reloaded)
	}

	// ── Delete album ──────────────────────────────────────────────────────────
	if ok, err := store.Albums.DeleteAlbum(ctx, albumRec, owner); err != nil || !ok {
		t.Fatalf("delete album: ok=%v err=%v", ok, err)
	}
	if reloaded, _ := store.Albums.GetAlbum(ctx, albumRec, owner); reloaded != nil {
		t.Fatal("album survived delete")
	}
}
