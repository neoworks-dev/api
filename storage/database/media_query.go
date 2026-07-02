package database

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	gql_model "github.com/neoworks/auth/gql/model"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// dbMediaRow is the queryable metadata projection of a media record. The
// embedding_status subquery surfaces the lifecycle of the row's image embedding
// (NONE when no media_embedding exists yet).
type dbMediaRow struct {
	ID              *models.RecordID `json:"id,omitempty"`
	Filename        string           `json:"filename"`
	MimeType        string           `json:"mime_type"`
	Size            int64            `json:"size"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
	Thumbnail       *models.RecordID `json:"thumbnail,omitempty"`
	EmbeddingStatus *string          `json:"embedding_status,omitempty"`
	Favorite        bool             `json:"favorite"`
	CaptureDate     *time.Time       `json:"capture_date,omitempty"`
	Location        map[string]any   `json:"location,omitempty"`
	Exif            map[string]any   `json:"exif,omitempty"`
}

func (r *dbMediaRow) toGQL() *gql_model.Media {
	m := &gql_model.Media{
		ID:              recordIDString(r.ID),
		Filename:        r.Filename,
		MimeType:        r.MimeType,
		Size:            int(r.Size),
		CreatedAt:       r.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       r.UpdatedAt.Format(time.RFC3339),
		EmbeddingStatus: r.EmbeddingStatus,
		Favorite:        r.Favorite,
		Exif:            r.Exif,
	}
	if r.Thumbnail != nil {
		id := recordIDString(r.Thumbnail)
		m.ThumbnailID = &id
	}
	if r.CaptureDate != nil {
		captureDate := r.CaptureDate.Format(time.RFC3339)
		m.CaptureDate = &captureDate
	}
	if point, ok := geoPointFromObject(r.Location); ok {
		m.Location = point
	}
	return m
}

// geoPointFromObject converts a stored {lat, lng} object (JSON floats) into the
// GraphQL GeoPoint, skipping rows where either coordinate is missing.
func geoPointFromObject(obj map[string]any) (*gql_model.GeoPoint, bool) {
	if obj == nil {
		return nil, false
	}
	lat, latOK := obj["lat"].(float64)
	lng, lngOK := obj["lng"].(float64)
	if !latOK || !lngOK {
		return nil, false
	}
	return &gql_model.GeoPoint{Lat: lat, Lng: lng}, true
}

// The projected columns shared by the list query and search-result hydration. The
// embedding_status subquery runs per row against media_embedding.
const mediaSelectFields = `id, filename, mime_type, size, created_at, updated_at, thumbnail,
	capture_date, effective_date, location, exif,
	(SELECT VALUE status FROM media_embedding WHERE media = $parent.id LIMIT 1)[0] AS embedding_status,
	(count((SELECT VALUE id FROM media_favorite WHERE media = $parent.id AND user = $user)) > 0) AS favorite`

// mediaListConditions builds the WHERE clause + bound params shared by list and
// count. `shared` switches the ownership scope: owned media (user = me) vs media
// granted to me (via media_grant). The structured filter compiles the same way for
// both.
func mediaListConditions(userID models.RecordID, shared bool, filter *gql_model.MediaFilter) ([]string, map[string]any, error) {
	queryParams := map[string]any{"user": userID}
	var conditions []string
	if shared {
		conditions = []string{"id IN (SELECT VALUE media FROM media_grant WHERE recipient = $user)"}
	} else {
		conditions = []string{"user = $user"}
	}
	// Derived media (thumbnails) are linked from their parent and never listed.
	conditions = append(conditions, "purpose != 'thumbnail'")

	if filter != nil {
		compiler := newFilterCompiler()
		expr := mediaFilterEngine.compile(compiler, filter)
		if compiler.err != nil {
			return nil, nil, compiler.err
		}
		if expr != "" {
			conditions = append(conditions, expr)
			for name, value := range compiler.params {
				queryParams[name] = value
			}
		}
	}
	return conditions, queryParams, nil
}

var mediaSortColumns = map[gql_model.MediaSortField]string{
	gql_model.MediaSortFieldFilename:  "filename",
	gql_model.MediaSortFieldCreatedAt: "created_at",
	gql_model.MediaSortFieldUpdatedAt: "updated_at",
	gql_model.MediaSortFieldSize:      "size",
	// Photos with no EXIF date fall back to their upload time (effective_date =
	// capture_date OR created_at) so they interleave by recency instead of sinking
	// below every dated photo. ORDER BY needs a plain field, hence the stored column.
	gql_model.MediaSortFieldCaptureDate: "effective_date",
}

// mediaOrderByClause builds "ORDER BY col [DESC], …", defaulting to newest first.
func mediaOrderByClause(sort []*gql_model.MediaSort) (string, error) {
	if len(sort) == 0 {
		return "ORDER BY created_at DESC", nil
	}
	parts := make([]string, 0, len(sort))
	for _, key := range sort {
		col, ok := mediaSortColumns[key.Field]
		if !ok {
			return "", fmt.Errorf("unsortable field %q", key.Field)
		}
		clause := col
		if key.Direction != nil && *key.Direction == gql_model.SortDirectionDesc {
			clause += " DESC"
		}
		parts = append(parts, clause)
	}
	return "ORDER BY " + strings.Join(parts, ", "), nil
}

// ListMediaQuery returns media metadata for owned (shared=false) or shared-with-me
// (shared=true) media, filtered/sorted/paged. Bytes stay encrypted; this is the
// metadata layer only.
func (s *SurrealStore) ListMediaQuery(ctx context.Context, userID models.RecordID, shared bool, filter *gql_model.MediaFilter, sort []*gql_model.MediaSort, limit, offset int) ([]*gql_model.Media, error) {
	conditions, queryParams, err := mediaListConditions(userID, shared, filter)
	if err != nil {
		return nil, err
	}
	orderBy, err := mediaOrderByClause(sort)
	if err != nil {
		return nil, err
	}
	queryParams["limit"] = limit
	queryParams["offset"] = offset
	query := "SELECT " + mediaSelectFields + " FROM media WHERE " +
		strings.Join(conditions, " AND ") + " " + orderBy + " LIMIT $limit START $offset"

	results, err := surrealdb.Query[[]dbMediaRow](ctx, s.DB, query, queryParams)
	if err != nil {
		return nil, fmt.Errorf("list media: %w", err)
	}
	for _, qr := range *results {
		out := make([]*gql_model.Media, len(qr.Result))
		for i := range qr.Result {
			out[i] = qr.Result[i].toGQL()
		}
		return out, nil
	}
	return nil, nil
}

// CountMediaQuery counts media matching the same scope/filter as ListMediaQuery.
func (s *SurrealStore) CountMediaQuery(ctx context.Context, userID models.RecordID, shared bool, filter *gql_model.MediaFilter) (int, error) {
	conditions, queryParams, err := mediaListConditions(userID, shared, filter)
	if err != nil {
		return 0, err
	}
	query := "SELECT count() AS count FROM media WHERE " + strings.Join(conditions, " AND ") + " GROUP ALL"
	results, err := surrealdb.Query[[]struct {
		Count int `json:"count"`
	}](ctx, s.DB, query, queryParams)
	if err != nil {
		return 0, fmt.Errorf("count media: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0].Count, nil
		}
	}
	return 0, nil
}

// ── Hybrid search ─────────────────────────────────────────────────────────────

type dbMediaSearchRow struct {
	Media *models.RecordID `json:"media,omitempty"`
	Score float64          `json:"score"`
}

// SearchMedia runs a vector arm (image embeddings) and a lexical arm (filename
// BM25) over the caller's owned media and fuses them with RRF. queryVec may be nil
// when no embedder is configured — the lexical arm still runs. Returns distinct
// media ranked by fused score.
func (s *SurrealStore) SearchMedia(ctx context.Context, userID models.RecordID, queryVec []float32, queryText string, limit int) ([]*gql_model.Media, error) {
	if limit <= 0 {
		limit = 20
	}
	pool := limit * 4
	if pool < 20 {
		pool = 20
	}

	var vectorRows, lexicalRows []dbMediaSearchRow
	var err error

	if len(queryVec) > 0 {
		// Approximate-nearest-neighbour over the HNSW index (idx_media_embedding_hnsw):
		// take the pool's worth of closest image embeddings via the KNN operator, then
		// present them newest-first. ef sits above the pool so recall stays high.
		ef := pool * 2
		vectorRows, err = s.runMediaSearch(ctx, fmt.Sprintf(`
			SELECT media, capture_date, vector::distance::knn() AS score
			FROM media_embedding
			WHERE user = $user AND status = 'ready' AND embedding != NONE
				AND embedding <|%d,%d|> $q
			ORDER BY capture_date DESC LIMIT %d`, pool, ef, pool),
			map[string]any{"user": userID, "q": queryVec})
		if err != nil {
			return nil, err
		}
	}

	if strings.TrimSpace(queryText) != "" {
		lexicalRows, err = s.runMediaSearch(ctx, fmt.Sprintf(`
			SELECT id AS media, search::score(1) AS score
			FROM media
			WHERE user = $user AND purpose != 'thumbnail' AND filename @1@ $query
			ORDER BY score DESC LIMIT %d`, pool),
			map[string]any{"user": userID, "query": queryText})
		if err != nil {
			return nil, err
		}
	}

	ranked := fuseMediaRRF(vectorRows, lexicalRows, limit)
	if len(ranked) == 0 {
		return nil, nil
	}
	return s.loadMediaHits(ctx, userID, ranked)
}

func (s *SurrealStore) runMediaSearch(ctx context.Context, query string, params map[string]any) ([]dbMediaSearchRow, error) {
	results, err := surrealdb.Query[[]dbMediaSearchRow](ctx, s.DB, query, params)
	if err != nil {
		return nil, fmt.Errorf("search media: %w", err)
	}
	for _, qr := range *results {
		return qr.Result, nil
	}
	return nil, nil
}

// fuseMediaRRF merges the ranked arms by sum(1/(rrfK + rank)); each media scores
// once per arm (rows are pre-sorted by score). Returns media ids in fused order.
func fuseMediaRRF(vectorRows, lexicalRows []dbMediaSearchRow, limit int) []string {
	scores := map[string]float64{}
	accumulate := func(rows []dbMediaSearchRow) {
		seen := map[string]bool{}
		rank := 0
		for _, r := range rows {
			if r.Media == nil {
				continue
			}
			id := fmt.Sprintf("%v", r.Media.ID)
			if seen[id] {
				continue
			}
			seen[id] = true
			rank++
			scores[id] += 1.0 / float64(rrfK+rank)
		}
	}
	accumulate(vectorRows)
	accumulate(lexicalRows)

	ids := make([]string, 0, len(scores))
	for id := range scores {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if scores[ids[i]] == scores[ids[j]] {
			return ids[i] < ids[j]
		}
		return scores[ids[i]] > scores[ids[j]]
	})
	if len(ids) > limit {
		ids = ids[:limit]
	}
	return ids
}

// loadMediaHits hydrates media metadata for the ranked ids and returns them in
// ranked order (dropping any deleted between search and load).
func (s *SurrealStore) loadMediaHits(ctx context.Context, userID models.RecordID, rankedIDs []string) ([]*gql_model.Media, error) {
	ids := make([]models.RecordID, len(rankedIDs))
	for i, id := range rankedIDs {
		ids[i] = models.NewRecordID("media", id)
	}
	query := "SELECT " + mediaSelectFields + " FROM media WHERE id IN $ids AND user = $user"
	results, err := surrealdb.Query[[]dbMediaRow](ctx, s.DB, query,
		map[string]any{"ids": ids, "user": userID})
	if err != nil {
		return nil, fmt.Errorf("load media hits: %w", err)
	}

	byID := map[string]*gql_model.Media{}
	for _, qr := range *results {
		for i := range qr.Result {
			m := qr.Result[i].toGQL()
			byID[m.ID] = m
		}
	}

	out := make([]*gql_model.Media, 0, len(rankedIDs))
	for _, id := range rankedIDs {
		if m, ok := byID[id]; ok {
			out = append(out, m)
		}
	}
	return out, nil
}

// ── Favorites & album membership listing ──────────────────────────────────────

// mediaMembershipQuery builds a "SELECT … FROM media WHERE id IN (<edge subquery>)"
// with the shared projection, owner scope, thumbnail exclusion, ordering + paging.
func mediaMembershipQuery(edgeSubquery, orderBy string) string {
	return "SELECT " + mediaSelectFields + " FROM media" +
		" WHERE id IN (" + edgeSubquery + ") AND user = $user AND purpose != 'thumbnail' " +
		orderBy + " LIMIT $limit START $offset"
}

func (s *SurrealStore) runMediaListQuery(ctx context.Context, query string, params map[string]any) ([]*gql_model.Media, error) {
	results, err := surrealdb.Query[[]dbMediaRow](ctx, s.DB, query, params)
	if err != nil {
		return nil, fmt.Errorf("list media: %w", err)
	}
	for _, qr := range *results {
		out := make([]*gql_model.Media, len(qr.Result))
		for i := range qr.Result {
			out[i] = qr.Result[i].toGQL()
		}
		return out, nil
	}
	return nil, nil
}

// ListFavoriteMedia returns the caller's favorited media (excludes thumbnails).
func (s *SurrealStore) ListFavoriteMedia(ctx context.Context, userID models.RecordID, sort []*gql_model.MediaSort, limit, offset int) ([]*gql_model.Media, error) {
	orderBy, err := mediaOrderByClause(sort)
	if err != nil {
		return nil, err
	}
	query := mediaMembershipQuery("SELECT VALUE media FROM media_favorite WHERE user = $user", orderBy)
	return s.runMediaListQuery(ctx, query, map[string]any{"user": userID, "limit": limit, "offset": offset})
}

// ListAlbumMedia returns the media in an album the caller owns (excludes thumbnails).
func (s *SurrealStore) ListAlbumMedia(ctx context.Context, albumID, userID models.RecordID, sort []*gql_model.MediaSort, limit, offset int) ([]*gql_model.Media, error) {
	orderBy, err := mediaOrderByClause(sort)
	if err != nil {
		return nil, err
	}
	query := mediaMembershipQuery("SELECT VALUE media FROM album_media WHERE album = $album AND user = $user", orderBy)
	return s.runMediaListQuery(ctx, query, map[string]any{
		"album": albumID, "user": userID, "limit": limit, "offset": offset,
	})
}

// SetMediaFavorite stars/unstars a media object the caller owns. The edge create
// is idempotent (DELETE then CREATE), and the media row is re-selected so its
// favorite flag reflects the change. Returns ErrNotFound for unowned/missing media.
func (s *SurrealStore) SetMediaFavorite(ctx context.Context, mediaID, userID models.RecordID, favorite bool) (*gql_model.Media, error) {
	// Gate the create on ownership inline (no THROW — driver error propagation is
	// version-dependent). DELETE is a no-op for unowned media; a missing/unowned
	// media simply yields no reload row below → ErrNotFound.
	mutation := `
		BEGIN TRANSACTION;
		LET $owned = (SELECT VALUE id FROM media WHERE id = $media AND user = $user);
		DELETE media_favorite WHERE user = $user AND media = $media;
		IF $favorite AND array::len($owned) > 0 { CREATE media_favorite SET user = $user, media = $media; };
		COMMIT TRANSACTION;`
	if _, err := surrealdb.Query[[]any](ctx, s.DB, mutation,
		map[string]any{"media": mediaID, "user": userID, "favorite": favorite}); err != nil {
		return nil, fmt.Errorf("set media favorite: %w", err)
	}

	query := "SELECT " + mediaSelectFields + " FROM media WHERE id = $media AND user = $user LIMIT 1"
	results, err := surrealdb.Query[[]dbMediaRow](ctx, s.DB, query,
		map[string]any{"media": mediaID, "user": userID})
	if err != nil {
		return nil, fmt.Errorf("set media favorite: reload: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0].toGQL(), nil
		}
	}
	return nil, ErrNotFound
}

// ── Client-side embedding fill ────────────────────────────────────────────────

// PendingMediaEmbedding is an embedding job the browser indexer must complete:
// download + decrypt the media, run the vision model, upload the vector.
type PendingMediaEmbedding struct {
	MediaID  string `json:"media_id"`
	MimeType string `json:"mime_type"`
	Modality string `json:"modality"`
}

type dbPendingMediaEmbedding struct {
	Media    *models.RecordID `json:"media,omitempty"`
	MimeType string           `json:"mime_type"`
	Modality string           `json:"modality"`
}

// ListPendingMediaEmbeddings returns the caller's owned media whose embedding is
// still pending, for the in-browser indexer to fill. mime_type is resolved
// through the media record link.
func (s *SurrealStore) ListPendingMediaEmbeddings(ctx context.Context, userID models.RecordID, limit int) ([]PendingMediaEmbedding, error) {
	results, err := surrealdb.Query[[]dbPendingMediaEmbedding](ctx, s.DB, `
		SELECT media, modality, media.mime_type AS mime_type
		FROM media_embedding
		WHERE user = $user AND status = 'pending'
		LIMIT $limit`,
		map[string]any{"user": userID, "limit": limit})
	if err != nil {
		return nil, fmt.Errorf("list pending media embeddings: %w", err)
	}
	for _, qr := range *results {
		out := make([]PendingMediaEmbedding, 0, len(qr.Result))
		for _, r := range qr.Result {
			if r.Media == nil {
				continue
			}
			out = append(out, PendingMediaEmbedding{
				MediaID:  fmt.Sprintf("%v", r.Media.ID),
				MimeType: r.MimeType,
				Modality: r.Modality,
			})
		}
		return out, nil
	}
	return nil, nil
}

// SetMediaEmbeddingParams carries a client-computed vector for a media object.
type SetMediaEmbeddingParams struct {
	MediaID  string
	UserID   string
	Modality string
	Model    string
	Dim      int
	EmbedVer int
	Vector   []float32
	Content  *string
}

// SetMediaEmbedding stores a client-computed vector and marks the row ready.
// Owner-scoped: the caller must own the media (checked by the handler). Updates
// the existing pending row for the modality, or creates one if absent (e.g. a
// later OCR pass).
func (s *SurrealStore) SetMediaEmbedding(ctx context.Context, p *SetMediaEmbeddingParams) error {
	embedVer := p.EmbedVer
	if embedVer == 0 {
		embedVer = 1
	}
	params := map[string]any{
		"media":     models.NewRecordID("media", p.MediaID),
		"user":      models.NewRecordID("user", p.UserID),
		"modality":  p.Modality,
		"vector":    p.Vector,
		"model":     p.Model,
		"dim":       p.Dim,
		"embed_ver": embedVer,
	}
	// `content` is option<string>; omit the assignment when absent so it defaults
	// to NONE (a Go nil would marshal to NULL, which option<string> rejects — see
	// apps/api/CLAUDE.md). The same fragment is reused in both branches.
	contentAssign := ""
	if p.Content != nil {
		contentAssign = ", content = $content"
		params["content"] = *p.Content
	}

	query := fmt.Sprintf(`
		BEGIN TRANSACTION;
		LET $existing = (SELECT VALUE id FROM media_embedding
			WHERE media = $media AND user = $user AND modality = $modality LIMIT 1);
		IF array::len($existing) > 0 {
			UPDATE $existing[0] SET
				embedding = $vector, model = $model, dim = $dim,
				embed_ver = $embed_ver%[1]s,
				status = 'ready', retry_count = 0;
		} ELSE {
			CREATE media_embedding SET
				media = $media, user = $user, modality = $modality,
				embedding = $vector, model = $model, dim = $dim,
				embed_ver = $embed_ver%[1]s, status = 'ready';
		};
		COMMIT TRANSACTION;
	`, contentAssign)

	if _, err := surrealdb.Query[[]any](ctx, s.DB, query, params); err != nil {
		return fmt.Errorf("set media embedding: %w", err)
	}
	return nil
}
