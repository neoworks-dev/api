package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/neoworks/auth/oauth"
	"github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// CheckChunks returns the subset of hashes that are already stored for this user.
// Deduplication is intentionally per-user: AMK-encrypted ciphertext differs between users.
func (s *SurrealStore) CheckChunks(ctx context.Context, userID string, hashes []string) ([]string, error) {
	results, err := surrealdb.Query[[]oauth.Chunk](
		ctx, s.DB,
		"SELECT hash FROM chunk WHERE user = $user AND hash IN $hashes",
		map[string]any{
			"user":   models.NewRecordID("user", userID),
			"hashes": hashes,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("check chunks: %w", err)
	}
	for _, qr := range *results {
		known := make([]string, len(qr.Result))
		for i, c := range qr.Result {
			known[i] = c.Hash
		}
		return known, nil
	}
	return nil, nil
}

// CreateChunk persists a chunk record after it has been uploaded to object storage,
// adds its size to the owning user's running storage_used_bytes total, and opens a
// storage billing period for the chunk (atomically, in one transaction).
// ref_count starts at 0 (DEFAULT) — it is bumped once the chunk is attached to a file.
//
// The billing period is an open interval (end_time NONE) referencing the chunk;
// it is closed when the chunk is garbage-collected (see DeleteFile). Personal
// usage bills the user directly; the unit price + currency come from the rate
// card (pricing.json) and are locked into the row at creation time.
func (s *SurrealStore) CreateChunk(ctx context.Context, userID, hash string, size int64, storageKey string) (*oauth.Chunk, error) {
	const tier = "hot"
	results, err := surrealdb.Query[[]oauth.Chunk](ctx, s.DB, `
		BEGIN TRANSACTION;
		LET $chunk = (CREATE chunk SET
			user        = $user,
			hash        = $hash,
			size        = $size,
			storage_key = $storage_key
		)[0];
		UPDATE $user SET storage_used_bytes += $size;
		CREATE billing_storage_period SET
			billed_to  = $user,
			tier       = $tier,
			size_bytes = $size,
			unit_price = $unit_price,
			currency   = $currency,
			ref        = $chunk.id,
			start_time = time::now();
		RETURN [$chunk];
		COMMIT TRANSACTION;
	`, map[string]any{
		"user":        models.NewRecordID("user", userID),
		"hash":        hash,
		"size":        size,
		"storage_key": storageKey,
		"tier":        tier,
		"unit_price":  s.pricing.StoragePricePerGBMonth(tier),
		"currency":    s.pricing.Currency,
	})
	if err != nil {
		return nil, fmt.Errorf("create chunk: %w", err)
	}
	return lastResult(*results, "create chunk: no result returned")
}

// GetChunksByHashes fetches chunk records for this user, returned in the same order as hashes.
func (s *SurrealStore) GetChunksByHashes(ctx context.Context, userID string, hashes []string) ([]*oauth.Chunk, error) {
	results, err := surrealdb.Query[[]oauth.Chunk](
		ctx, s.DB,
		"SELECT * FROM chunk WHERE user = $user AND hash IN $hashes",
		map[string]any{
			"user":   models.NewRecordID("user", userID),
			"hashes": hashes,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("get chunks by hashes: %w", err)
	}

	byHash := make(map[string]*oauth.Chunk)
	for _, qr := range *results {
		for i := range qr.Result {
			c := &qr.Result[i]
			byHash[c.Hash] = c
		}
	}

	out := make([]*oauth.Chunk, 0, len(hashes))
	for _, h := range hashes {
		c, ok := byHash[h]
		if !ok {
			return nil, fmt.Errorf("chunk not found: %s", h)
		}
		out = append(out, c)
	}
	return out, nil
}

// GetChunkByHash fetches a single chunk record for this user, for retrieval/download.
func (s *SurrealStore) GetChunkByHash(ctx context.Context, userID, hash string) (*oauth.Chunk, error) {
	results, err := surrealdb.Query[[]oauth.Chunk](
		ctx, s.DB,
		"SELECT * FROM chunk WHERE user = $user AND hash = $hash LIMIT 1",
		map[string]any{
			"user": models.NewRecordID("user", userID),
			"hash": hash,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("get chunk by hash: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, ErrNotFound
}

// FileChunkRef is a chunk's content hash and size — the manifest the SDK needs
// to re-download and decrypt a file item.
type FileChunkRef struct {
	Hash string `json:"hash"`
	Size int64  `json:"size"`
}

// FileManifestData reassembles a file record into the manifest shape. The
// stored `chunks` are record links, so FETCH resolves their hashes. `WrappedDEK`
// is the requester's own sealed copy of the object's DEK (the recipient entry
// keyed by their user id), which their Vault can unseal to decrypt the chunks.
type FileManifestData struct {
	ID         string          `json:"id"`
	Filename   string          `json:"filename"`
	MimeType   string          `json:"mime_type"`
	Chunks     []FileChunkRef `json:"chunks"`
	WrappedDEK string          `json:"wrapped_dek"`
	// Scope the DEK is sealed under; empty ⇒ legacy account key. The client passes
	// it back to the key-holder so it picks the right scope key on decrypt.
	Scope string `json:"scope,omitempty"`
}

// GetFileManifest returns a file item's manifest if the requester is the owner
// OR holds a share grant on it. Chunk records stay owner-scoped; FETCH resolves
// their hashes regardless of who is reading.
func (s *SurrealStore) GetFileManifest(ctx context.Context, fileID, requesterID string) (*FileManifestData, error) {
	type row struct {
		ID         *models.RecordID       `json:"id"`
		Filename   string                 `json:"filename"`
		MimeType   string                 `json:"mime_type"`
		Chunks     []oauth.Chunk          `json:"chunks"`
		Recipients []oauth.FileRecipient `json:"recipients"`
		Scope      string                 `json:"scope"`
	}
	results, err := surrealdb.Query[[]row](
		ctx, s.DB,
		`SELECT id, filename, mime_type, chunks, recipients, scope FROM file
		 WHERE id = $id
		   AND (user = $user
		        OR id IN (SELECT VALUE file FROM file_grant WHERE recipient = $user))
		 LIMIT 1 FETCH chunks`,
		map[string]any{
			"id":   models.NewRecordID("file", fileID),
			"user": models.NewRecordID("user", requesterID),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("get file manifest: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) == 0 {
			continue
		}
		r := qr.Result[0]
		chunks := make([]FileChunkRef, len(r.Chunks))
		for i, c := range r.Chunks {
			chunks[i] = FileChunkRef{Hash: c.Hash, Size: c.Size}
		}
		id := fileID
		if r.ID != nil {
			id = fmt.Sprintf("%v", r.ID.ID)
		}
		wrappedDEK := ""
		for _, rcpt := range r.Recipients {
			if rcpt.KeyID == requesterID {
				wrappedDEK = rcpt.WrappedDEK
				break
			}
		}
		return &FileManifestData{ID: id, Filename: r.Filename, MimeType: r.MimeType, Chunks: chunks, WrappedDEK: wrappedDEK, Scope: r.Scope}, nil
	}
	return nil, ErrNotFound
}

// GetFileManifests is the batch form of GetFileManifest: it resolves every
// readable manifest for the given ids in a single query, so a whole grid page
// warms its manifests in one round-trip. Unreadable / missing ids are silently
// omitted. Order is not guaranteed.
func (s *SurrealStore) GetFileManifests(ctx context.Context, fileIDs []string, requesterID string) ([]FileManifestData, error) {
	if len(fileIDs) == 0 {
		return []FileManifestData{}, nil
	}
	type row struct {
		ID         *models.RecordID       `json:"id"`
		Filename   string                 `json:"filename"`
		MimeType   string                 `json:"mime_type"`
		Chunks     []oauth.Chunk          `json:"chunks"`
		Recipients []oauth.FileRecipient `json:"recipients"`
		Scope      string                 `json:"scope"`
	}
	ids := make([]models.RecordID, len(fileIDs))
	for i, id := range fileIDs {
		ids[i] = models.NewRecordID("file", id)
	}
	results, err := surrealdb.Query[[]row](
		ctx, s.DB,
		`SELECT id, filename, mime_type, chunks, recipients, scope FROM file
		 WHERE id IN $ids
		   AND (user = $user
		        OR id IN (SELECT VALUE file FROM file_grant WHERE recipient = $user))
		 FETCH chunks`,
		map[string]any{
			"ids":  ids,
			"user": models.NewRecordID("user", requesterID),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("get file manifests: %w", err)
	}
	out := []FileManifestData{}
	for _, qr := range *results {
		for _, r := range qr.Result {
			chunks := make([]FileChunkRef, len(r.Chunks))
			for i, c := range r.Chunks {
				chunks[i] = FileChunkRef{Hash: c.Hash, Size: c.Size}
			}
			id := ""
			if r.ID != nil {
				id = fmt.Sprintf("%v", r.ID.ID)
			}
			wrappedDEK := ""
			for _, rcpt := range r.Recipients {
				if rcpt.KeyID == requesterID {
					wrappedDEK = rcpt.WrappedDEK
					break
				}
			}
			out = append(out, FileManifestData{ID: id, Filename: r.Filename, MimeType: r.MimeType, Chunks: chunks, WrappedDEK: wrappedDEK, Scope: r.Scope})
		}
	}
	return out, nil
}

// GetReadableChunk fetches a single encrypted chunk for a reader who is either the
// file owner or a grant holder. The chunk must actually belong to `fileID` (a
// grant on one file never exposes the owner's other chunks). Chunks are stored
// under the owner, so the lookup resolves through the file's owner, not the
// requester.
func (s *SurrealStore) GetReadableChunk(ctx context.Context, fileID, hash, requesterID string) (*oauth.Chunk, error) {
	type fileRow struct {
		User   *models.RecordID  `json:"user"`
		Chunks []models.RecordID `json:"chunks"`
	}
	fileResults, err := surrealdb.Query[[]fileRow](
		ctx, s.DB,
		`SELECT user, chunks FROM file
		 WHERE id = $id
		   AND (user = $requester
		        OR id IN (SELECT VALUE file FROM file_grant WHERE recipient = $requester))
		 LIMIT 1`,
		map[string]any{
			"id":        models.NewRecordID("file", fileID),
			"requester": models.NewRecordID("user", requesterID),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("get readable chunk: file: %w", err)
	}
	var file *fileRow
	for _, qr := range *fileResults {
		if len(qr.Result) > 0 {
			file = &qr.Result[0]
			break
		}
	}
	if file == nil || file.User == nil {
		return nil, ErrNotFound
	}

	ownerID := fmt.Sprintf("%v", file.User.ID)
	chunk, err := s.GetChunkByHash(ctx, ownerID, hash)
	if err != nil {
		return nil, err
	}

	// Confirm the chunk is part of THIS file, not just any chunk the owner holds.
	if chunk.ID == nil || !containsRecordID(file.Chunks, *chunk.ID) {
		return nil, ErrNotFound
	}
	return chunk, nil
}

func containsRecordID(ids []models.RecordID, target models.RecordID) bool {
	for _, id := range ids {
		if id.Table == target.Table && fmt.Sprintf("%v", id.ID) == fmt.Sprintf("%v", target.ID) {
			return true
		}
	}
	return false
}

// GeoPoint is an unencrypted GPS coordinate stored on a file row, queryable via
// the GeoFilter. Sourced from a photo's EXIF GPS tags at upload time.
type GeoPoint struct {
	Lat float64 `json:"lat"`
	Lng float64 `json:"lng"`
}

type CreateFileParams struct {
	UserID     string
	Filename   string
	MimeType   string
	Size       int64
	ChunkIDs   []models.RecordID
	Recipients []oauth.FileRecipient
	// Scope is the encryption scope the object's DEK is sealed under (optional;
	// absent ⇒ legacy account key).
	Scope *string
	// ThumbnailID links a derived thumbnail file (optional).
	ThumbnailID *string
	// Purpose marks derived file (e.g. "thumbnail") so they are hidden from the
	// library listing and skipped by the embedding queue (optional).
	Purpose *string
	// CaptureDate is the photo's EXIF capture time (DateTimeOriginal), stored
	// unencrypted so it is queryable/sortable (optional).
	CaptureDate *time.Time
	// Location is the photo's EXIF GPS point, stored unencrypted (optional).
	Location *GeoPoint
	// Exif holds the full parsed EXIF tag set, stored unencrypted (optional).
	Exif map[string]any
}

// CreateFile runs the versioned create pattern from CLAUDE.md. `recipients`
// holds the sealed DEK wrappers — at minimum the owner's own copy. Optional
// thumbnail/purpose are omitted from the SET when absent (option<T> fields reject
// NULL — see CLAUDE.md).
func (s *SurrealStore) CreateFile(ctx context.Context, p *CreateFileParams) (*oauth.File, error) {
	params := map[string]any{
		"user":       models.NewRecordID("user", p.UserID),
		"filename":   p.Filename,
		"mime_type":  p.MimeType,
		"size":       p.Size,
		"chunks":     p.ChunkIDs,
		"recipients": p.Recipients,
	}

	fileExtra := ""
	if p.ThumbnailID != nil && *p.ThumbnailID != "" {
		fileExtra += ", thumbnail = type::record('file', $thumbnail_id)"
		params["thumbnail_id"] = *p.ThumbnailID
	}
	purpose := ""
	if p.Purpose != nil {
		purpose = *p.Purpose
	}
	if purpose != "" {
		fileExtra += ", purpose = $purpose"
		params["purpose"] = purpose
	}
	// Always bound for the embedding gate, even when not assigned to the row.
	params["purpose_gate"] = purpose

	// Encryption scope (option<string>): omitted from the SET when absent so it
	// defaults to NONE (legacy account key).
	if p.Scope != nil && *p.Scope != "" {
		fileExtra += ", scope = $scope"
		params["scope"] = *p.Scope
	}

	// Unencrypted EXIF metadata: each field is omitted from the SET when absent so
	// the option<T> column defaults to NONE (see CLAUDE.md optional-field rule).
	if p.CaptureDate != nil {
		fileExtra += ", capture_date = $capture_date"
		params["capture_date"] = *p.CaptureDate
	}
	if p.Location != nil {
		fileExtra += ", location = $location"
		params["location"] = map[string]any{"lat": p.Location.Lat, "lng": p.Location.Lng}
	}
	if len(p.Exif) > 0 {
		fileExtra += ", exif = $exif"
		params["exif"] = p.Exif
	}

	query := fmt.Sprintf(`
		BEGIN TRANSACTION;
		LET $file = (CREATE file SET
			user       = $user,
			filename   = $filename,
			mime_type  = $mime_type,
			size       = $size,
			chunks     = $chunks,
			recipients = $recipients%s
		)[0];
		LET $version = (CREATE file_version SET
			file_id   = $file.id,
			user       = $user,
			filename   = $filename,
			mime_type  = $mime_type,
			size       = $size,
			chunks     = $chunks,
			recipients = $recipients,
			scope      = $file.scope
		)[0];
		LET $result = (UPDATE $file.id SET version = $version.id)[0];
		FOR $c IN $chunks {
			UPDATE $c SET ref_count += 2;
		};
		-- Queue a client-side image embedding (the server can't decrypt the bytes).
		-- Thumbnails and other derived file are not embedded.
		IF string::starts_with($mime_type, 'image/') AND $purpose_gate != 'thumbnail' {
			CREATE file_embedding SET
				file    = $file.id,
				user     = $user,
				modality = 'image',
				status   = 'pending';
		};
		RETURN [$result];
		COMMIT TRANSACTION;
	`, fileExtra)

	results, err := surrealdb.Query[[]oauth.File](ctx, s.DB, query, params)
	if err != nil {
		return nil, fmt.Errorf("create file: %w", err)
	}
	return lastResult(*results, "create file: no result returned")
}

// ── Sharing ─────────────────────────────────────────────────────────────────

// CreateFileShare grants `recipientID` read access to `fileID` and appends the
// recipient's sealed DEK wrapper to the file. Owner-scoped: a non-owner (or a
// missing file) yields ErrNotFound. Idempotent on the wrapper — re-sharing
// replaces the recipient's existing wrapper rather than duplicating it.
func (s *SurrealStore) CreateFileShare(ctx context.Context, fileID, ownerID, recipientID, wrappedDEK string) error {
	if _, err := s.GetFile(ctx, fileID, ownerID); err != nil {
		return err // ErrNotFound when the caller does not own the file
	}
	_, err := surrealdb.Query[[]any](ctx, s.DB, `
		BEGIN TRANSACTION;
		UPDATE $file_id SET recipients = array::append(
			recipients[WHERE key_id != $recipient_key],
			{ key_id: $recipient_key, wrapped_dek: $wrapped_dek }
		);
		DELETE file_grant WHERE file = $file_id AND recipient = $recipient;
		CREATE file_grant SET file = $file_id, owner = $owner, recipient = $recipient;
		COMMIT TRANSACTION;
	`, map[string]any{
		"file_id":      models.NewRecordID("file", fileID),
		"owner":         models.NewRecordID("user", ownerID),
		"recipient":     models.NewRecordID("user", recipientID),
		"recipient_key": recipientID,
		"wrapped_dek":   wrappedDEK,
	})
	if err != nil {
		return fmt.Errorf("create file share: %w", err)
	}
	return nil
}

// DeleteFileShare revokes `recipientID`'s access to `fileID`: drops the grant
// and removes their sealed DEK wrapper. Owner-scoped. Does not rotate the DEK, so
// content the recipient already fetched is not protected.
func (s *SurrealStore) DeleteFileShare(ctx context.Context, fileID, ownerID, recipientID string) error {
	if _, err := s.GetFile(ctx, fileID, ownerID); err != nil {
		return err // ErrNotFound when the caller does not own the file
	}
	_, err := surrealdb.Query[[]any](ctx, s.DB, `
		BEGIN TRANSACTION;
		UPDATE $file_id SET recipients = recipients[WHERE key_id != $recipient_key];
		DELETE file_grant WHERE file = $file_id AND recipient = $recipient;
		COMMIT TRANSACTION;
	`, map[string]any{
		"file_id":      models.NewRecordID("file", fileID),
		"recipient":     models.NewRecordID("user", recipientID),
		"recipient_key": recipientID,
	})
	if err != nil {
		return fmt.Errorf("delete file share: %w", err)
	}
	return nil
}

type UpdateFileParams struct {
	FileID         string
	UserID          string
	ParentVersionID models.RecordID
	Filename        *string
	MimeType        *string
	Size            *int64
	ChunkIDs        []models.RecordID
}

// UpdateFile runs the versioned update pattern from CLAUDE.md.
// The caller supplies the parent version ID to build the derived_from graph.
func (s *SurrealStore) UpdateFile(ctx context.Context, p *UpdateFileParams) (*oauth.File, error) {
	results, err := surrealdb.Query[[]oauth.File](ctx, s.DB, `
		BEGIN TRANSACTION;
		LET $current = (SELECT * FROM file WHERE id = $id AND user = $user LIMIT 1)[0];
		IF $current = NONE { RETURN NONE };
		LET $new_version = (CREATE file_version SET
			file_id  = $id,
			user      = $user,
			filename  = $filename  ?? $current.filename,
			mime_type = $mime_type ?? $current.mime_type,
			size      = $size      ?? $current.size,
			chunks    = $chunks    ?? $current.chunks
		)[0];
		RELATE $parent->derived_from->$new_version.id;
		LET $result = (UPDATE $id SET
			filename  = $filename  ?? $current.filename,
			mime_type = $mime_type ?? $current.mime_type,
			size      = $size      ?? $current.size,
			chunks    = $chunks    ?? $current.chunks,
			version   = $new_version.id
		)[0];

		-- ref_count tracks array-slot references across file.chunks + file_version.chunks.
		-- $new_version always adds one slot per chunk in $effective; chunks newly added to
		-- file.chunks add a second slot, chunks dropped from file.chunks lose one.
		LET $effective = $chunks ?? $current.chunks;
		LET $added     = array::complement($effective, $current.chunks);
		LET $removed   = array::complement($current.chunks, $effective);
		FOR $c IN $effective { UPDATE $c SET ref_count += 1 };
		FOR $c IN $added     { UPDATE $c SET ref_count += 1 };
		FOR $c IN $removed   { UPDATE $c SET ref_count -= 1 };

		RETURN [$result];
		COMMIT TRANSACTION;
	`, map[string]any{
		"id":        models.NewRecordID("file", p.FileID),
		"user":      models.NewRecordID("user", p.UserID),
		"parent":    p.ParentVersionID,
		"filename":  derefStr(p.Filename),
		"mime_type": derefStr(p.MimeType),
		"size":      derefInt64(p.Size),
		"chunks":    nilIfEmpty(p.ChunkIDs),
	})
	if err != nil {
		return nil, fmt.Errorf("update file: %w", err)
	}
	m, err := lastResult(*results, "")
	if err != nil {
		return nil, ErrNotFound
	}
	return m, nil
}

func (s *SurrealStore) GetFile(ctx context.Context, fileID, userID string) (*oauth.File, error) {
	results, err := surrealdb.Query[[]oauth.File](
		ctx, s.DB,
		"SELECT * FROM file WHERE id = $id AND user = $user LIMIT 1",
		map[string]any{
			"id":   models.NewRecordID("file", fileID),
			"user": models.NewRecordID("user", userID),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("get file: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, ErrNotFound
}

type chunkDecrement struct {
	Chunk models.RecordID `json:"chunk"`
	Count int             `json:"count"`
}

// GCChunk identifies a chunk whose ref_count dropped to <= 0 during a delete,
// meaning its object-storage blob is now safe to remove.
type GCChunk struct {
	ID         models.RecordID `json:"id"`
	Size       int64           `json:"size"`
	StorageKey string          `json:"storage_key"`
}

// DeleteFile removes a file item, its full version history, and the
// derived_from edges between those versions. Every chunk referenced by the
// current file.chunks or any file_version.chunks has ref_count decremented
// by the number of array slots it occupied; chunks whose ref_count drops to
// <= 0 are deleted from the chunk table and their bytes subtracted from the
// user's storage_used_bytes. The caller is responsible for deleting the
// returned chunks' blobs from object storage.
func (s *SurrealStore) DeleteFile(ctx context.Context, fileID, userID string) ([]GCChunk, error) {
	current, err := s.GetFile(ctx, fileID, userID)
	if err != nil {
		return nil, err // ErrNotFound or wrapped query error
	}

	fileRec := models.NewRecordID("file", fileID)
	userRec := models.NewRecordID("user", userID)

	// Capture the linked thumbnail (if any) so it is cascade-deleted after the
	// parent. Thumbnails are their own file objects with their own chunks.
	var thumbnailID string
	thumbRes, err := surrealdb.Query[[]struct {
		Thumbnail *models.RecordID `json:"thumbnail"`
	}](
		ctx, s.DB,
		"SELECT thumbnail FROM file WHERE id = $id AND user = $user LIMIT 1",
		map[string]any{"id": fileRec, "user": userRec},
	)
	if err != nil {
		return nil, fmt.Errorf("delete file: get thumbnail: %w", err)
	}
	for _, qr := range *thumbRes {
		if len(qr.Result) > 0 && qr.Result[0].Thumbnail != nil {
			thumbnailID = fmt.Sprintf("%v", qr.Result[0].Thumbnail.ID)
		}
	}

	type versionChunks struct {
		Chunks []models.RecordID `json:"chunks"`
	}
	versionResults, err := surrealdb.Query[[]versionChunks](
		ctx, s.DB,
		"SELECT chunks FROM file_version WHERE file_id = $id AND user = $user",
		map[string]any{"id": fileRec, "user": userRec},
	)
	if err != nil {
		return nil, fmt.Errorf("delete file: get versions: %w", err)
	}

	// Tally how many array slots (file.chunks + every file_version.chunks)
	// reference each chunk; ref_count drops by that amount.
	counts := make(map[string]int)
	idByKey := make(map[string]models.RecordID)
	tally := func(ids []models.RecordID) {
		for _, id := range ids {
			key := fmt.Sprintf("%s:%v", id.Table, id.ID)
			counts[key]++
			idByKey[key] = id
		}
	}
	tally(current.Chunks)
	for _, qr := range *versionResults {
		for _, v := range qr.Result {
			tally(v.Chunks)
		}
	}

	chunkIDs := make([]models.RecordID, 0, len(counts))
	for _, id := range idByKey {
		chunkIDs = append(chunkIDs, id)
	}

	// Snapshot ref_count/size/storage_key now, before the delete transaction.
	// SurrealDB transactions read from a snapshot taken at BEGIN, so a SELECT
	// after an UPDATE in the same transaction would not see the decremented
	// value -- the dead/alive split has to be decided up front instead.
	chunkResults, err := surrealdb.Query[[]oauth.Chunk](
		ctx, s.DB,
		"SELECT id, size, storage_key, ref_count FROM chunk WHERE id IN $chunk_ids AND user = $user",
		map[string]any{"chunk_ids": chunkIDs, "user": userRec},
	)
	if err != nil {
		return nil, fmt.Errorf("delete file: get chunks: %w", err)
	}

	aliveDecrements := make([]chunkDecrement, 0, len(counts))
	deadIDs := make([]models.RecordID, 0, len(counts))
	dead := make([]GCChunk, 0, len(counts))
	var deadSize int64
	for _, qr := range *chunkResults {
		for _, c := range qr.Result {
			key := fmt.Sprintf("%s:%v", c.ID.Table, c.ID.ID)
			count := counts[key]
			if c.RefCount-int64(count) <= 0 {
				deadIDs = append(deadIDs, *c.ID)
				dead = append(dead, GCChunk{ID: *c.ID, Size: c.Size, StorageKey: c.StorageKey})
				deadSize += c.Size
			} else {
				aliveDecrements = append(aliveDecrements, chunkDecrement{Chunk: *c.ID, Count: count})
			}
		}
	}

	_, err = surrealdb.Query[[]any](ctx, s.DB, `
		BEGIN TRANSACTION;
		LET $version_ids = (SELECT VALUE id FROM file_version WHERE file_id = $id AND user = $user);
		DELETE derived_from WHERE in IN $version_ids OR out IN $version_ids;
		DELETE file_embedding WHERE file = $id AND user = $user;
		DELETE file_favorite WHERE file = $id AND user = $user;
		DELETE album_file WHERE file = $id AND user = $user;
		DELETE file_version WHERE file_id = $id AND user = $user;
		DELETE file WHERE id = $id AND user = $user;

		FOR $d IN $alive_decrements {
			UPDATE $d.chunk SET ref_count -= $d.count;
		};

		-- Close the open storage billing period for each chunk being removed,
		-- so it stops accruing GB-months from now.
		UPDATE billing_storage_period SET end_time = time::now()
			WHERE ref IN $dead_ids AND end_time = NONE;

		DELETE chunk WHERE id IN $dead_ids AND user = $user;
		UPDATE $user SET storage_used_bytes -= $dead_size;
		COMMIT TRANSACTION;
	`, map[string]any{
		"id":               fileRec,
		"user":             userRec,
		"alive_decrements": aliveDecrements,
		"dead_ids":         deadIDs,
		"dead_size":        deadSize,
	})
	if err != nil {
		return nil, fmt.Errorf("delete file: %w", err)
	}

	// Cascade: delete the linked thumbnail file (and its chunks). Tolerate an
	// already-removed thumbnail.
	if thumbnailID != "" {
		thumbDead, terr := s.DeleteFile(ctx, thumbnailID, userID)
		if terr != nil && !errors.Is(terr, ErrNotFound) {
			return nil, fmt.Errorf("delete file: thumbnail: %w", terr)
		}
		dead = append(dead, thumbDead...)
	}

	return dead, nil
}

func (s *SurrealStore) ListFile(ctx context.Context, userID string, limit, offset int) ([]*oauth.File, error) {
	results, err := surrealdb.Query[[]oauth.File](
		ctx, s.DB,
		"SELECT * FROM file WHERE user = $user ORDER BY capture_date DESC LIMIT $limit START $offset",
		map[string]any{
			"user":   models.NewRecordID("user", userID),
			"limit":  limit,
			"offset": offset,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list file: %w", err)
	}
	for _, qr := range *results {
		out := make([]*oauth.File, len(qr.Result))
		for i := range qr.Result {
			out[i] = &qr.Result[i]
		}
		return out, nil
	}
	return nil, nil
}

// lastResult returns the last non-empty result in a multi-statement query
// response. RELATE and other intermediate statements can produce decodable
// (but wrong) results before the final RETURN [$result].
func lastResult[T any](results []surrealdb.QueryResult[[]T], emptyMsg string) (*T, error) {
	var last *T
	for i := range results {
		if len(results[i].Result) > 0 {
			last = &results[i].Result[0]
		}
	}
	if last == nil {
		if emptyMsg != "" {
			return nil, fmt.Errorf("%s", emptyMsg)
		}
		return nil, fmt.Errorf("no result")
	}
	return last, nil
}

// derefStr returns the pointed-to string or nil so the CBOR encoder sees a
// concrete string (not *string) and encodes it correctly for SurrealDB params.
func derefStr(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func derefInt64(n *int64) any {
	if n == nil {
		return nil
	}
	return *n
}

func nilIfEmpty(ids []models.RecordID) any {
	if len(ids) == 0 {
		return nil
	}
	return ids
}
