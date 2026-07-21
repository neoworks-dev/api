package database

import (
	"fmt"
	"time"

	"context"

	gql_model "github.com/neoworks/auth/gql/model"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// AlbumStore owns the album + album_file tables: flat, user-owned, non-versioned
// collections of file. Cover and count are derived per query (no denormalized
// fields to keep in sync).
type AlbumStore struct {
	DB *surrealdb.DB
}

type dbAlbumRow struct {
	ID        *models.RecordID `json:"id,omitempty"`
	Name      string           `json:"name"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
	Count     int              `json:"count"`
	Cover     *models.RecordID `json:"cover,omitempty"`
}

func (r *dbAlbumRow) toGQL() *gql_model.Album {
	album := &gql_model.Album{
		ID:        recordIDString(r.ID),
		Name:      r.Name,
		CreatedAt: r.CreatedAt.Format(time.RFC3339),
		UpdatedAt: r.UpdatedAt.Format(time.RFC3339),
		Count:     r.Count,
	}
	if r.Cover != nil {
		cover := recordIDString(r.Cover)
		album.CoverThumbnailID = &cover
	}
	return album
}

// albumSelectFields derives count + cover via correlated subqueries on $parent.id
// (mirrors fileSelectFields' embedding_status). Cover is the most-recently-added
// member's thumbnail (NONE → null cover).
// The cover subquery selects created_at alongside the thumbnail because SurrealDB
// requires the ORDER BY idiom to appear in the projection; we then pluck `.cover`.
const albumSelectFields = `id, name, created_at, updated_at,
	array::len((SELECT VALUE id FROM album_file WHERE album = $parent.id)) AS count,
	(SELECT file.thumbnail AS cover, created_at FROM album_file WHERE album = $parent.id ORDER BY created_at DESC LIMIT 1)[0].cover AS cover`

func firstAlbum(results *[]surrealdb.QueryResult[[]dbAlbumRow]) *gql_model.Album {
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0].toGQL()
		}
	}
	return nil
}

// ListAlbums returns the caller's albums, newest first.
func (s *AlbumStore) ListAlbums(ctx context.Context, user models.RecordID) ([]*gql_model.Album, error) {
	query := "SELECT " + albumSelectFields + " FROM album WHERE user = $user ORDER BY created_at DESC"
	results, err := surrealdb.Query[[]dbAlbumRow](ctx, s.DB, query, map[string]any{"user": user})
	if err != nil {
		return nil, fmt.Errorf("list albums: %w", err)
	}
	for _, qr := range *results {
		out := make([]*gql_model.Album, len(qr.Result))
		for i := range qr.Result {
			out[i] = qr.Result[i].toGQL()
		}
		return out, nil
	}
	return nil, nil
}

// GetAlbum returns one album the caller owns, or nil.
func (s *AlbumStore) GetAlbum(ctx context.Context, id, user models.RecordID) (*gql_model.Album, error) {
	query := "SELECT " + albumSelectFields + " FROM album WHERE id = $id AND user = $user LIMIT 1"
	results, err := surrealdb.Query[[]dbAlbumRow](ctx, s.DB, query, map[string]any{"id": id, "user": user})
	if err != nil {
		return nil, fmt.Errorf("get album: %w", err)
	}
	return firstAlbum(results), nil
}

// CreateAlbum creates an empty album and returns it (count 0, no cover).
func (s *AlbumStore) CreateAlbum(ctx context.Context, user models.RecordID, name string) (*gql_model.Album, error) {
	created, err := surrealdb.Query[[]struct {
		ID *models.RecordID `json:"id,omitempty"`
	}](ctx, s.DB, "CREATE album SET user = $user, name = $name RETURN AFTER",
		map[string]any{"user": user, "name": name})
	if err != nil {
		return nil, fmt.Errorf("create album: %w", err)
	}
	for _, qr := range *created {
		if len(qr.Result) > 0 && qr.Result[0].ID != nil {
			return s.GetAlbum(ctx, *qr.Result[0].ID, user)
		}
	}
	return nil, fmt.Errorf("create album: no result returned")
}

// RenameAlbum renames an album the caller owns, returning the updated album.
func (s *AlbumStore) RenameAlbum(ctx context.Context, id, user models.RecordID, name string) (*gql_model.Album, error) {
	if _, err := surrealdb.Query[[]any](ctx, s.DB,
		"UPDATE album SET name = $name WHERE id = $id AND user = $user",
		map[string]any{"id": id, "user": user, "name": name}); err != nil {
		return nil, fmt.Errorf("rename album: %w", err)
	}
	album, err := s.GetAlbum(ctx, id, user)
	if err != nil {
		return nil, err
	}
	if album == nil {
		return nil, ErrNotFound
	}
	return album, nil
}

// DeleteAlbum drops the album and all its membership edges (the file stay).
func (s *AlbumStore) DeleteAlbum(ctx context.Context, id, user models.RecordID) (bool, error) {
	_, err := surrealdb.Query[[]any](ctx, s.DB, `
		BEGIN TRANSACTION;
		DELETE album_file WHERE album = $id AND user = $user;
		DELETE album WHERE id = $id AND user = $user;
		COMMIT TRANSACTION;`,
		map[string]any{"id": id, "user": user})
	if err != nil {
		return false, fmt.Errorf("delete album: %w", err)
	}
	return true, nil
}

// AddFileToAlbum idempotently links the caller's file into an album the caller
// owns (foreign file is skipped). Returns the updated album.
func (s *AlbumStore) AddFileToAlbum(ctx context.Context, albumID, user models.RecordID, fileIDs []models.RecordID) (*gql_model.Album, error) {
	_, err := surrealdb.Query[[]any](ctx, s.DB, `
		BEGIN TRANSACTION;
		LET $owns_album = (SELECT VALUE id FROM album WHERE id = $album AND user = $user);
		IF array::len($owns_album) > 0 {
			FOR $m IN $file {
				LET $owned = (SELECT VALUE id FROM file WHERE id = $m AND user = $user);
				IF array::len($owned) > 0 {
					DELETE album_file WHERE album = $album AND file = $m;
					CREATE album_file SET album = $album, file = $m, user = $user;
				};
			};
			UPDATE $album SET updated_at = time::now();
		};
		COMMIT TRANSACTION;`,
		map[string]any{"album": albumID, "user": user, "file": fileIDs})
	if err != nil {
		return nil, fmt.Errorf("add file to album: %w", err)
	}
	album, err := s.GetAlbum(ctx, albumID, user)
	if err != nil {
		return nil, err
	}
	if album == nil {
		return nil, ErrNotFound
	}
	return album, nil
}

// RemoveFileFromAlbum drops the given file from an album the caller owns.
// Returns the updated album.
func (s *AlbumStore) RemoveFileFromAlbum(ctx context.Context, albumID, user models.RecordID, fileIDs []models.RecordID) (*gql_model.Album, error) {
	_, err := surrealdb.Query[[]any](ctx, s.DB, `
		BEGIN TRANSACTION;
		DELETE album_file WHERE album = $album AND file IN $file AND user = $user;
		UPDATE album SET updated_at = time::now() WHERE id = $album AND user = $user;
		COMMIT TRANSACTION;`,
		map[string]any{"album": albumID, "user": user, "file": fileIDs})
	if err != nil {
		return nil, fmt.Errorf("remove file from album: %w", err)
	}
	album, err := s.GetAlbum(ctx, albumID, user)
	if err != nil {
		return nil, err
	}
	if album == nil {
		return nil, ErrNotFound
	}
	return album, nil
}
