package database

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// Item is one encrypted envelope, whatever collection its space holds. The
// server never sees the content — `Blob` is ciphertext, `Sig` the author's
// Ed25519 signature. `VersionID` names the version row holding this item's
// current content.
type Item struct {
	ID        string    `json:"item_id"`
	SpaceID   string    `json:"space_id"`
	Seq       int       `json:"seq"`
	BaseSeq   int       `json:"base_seq"`
	KeyEpoch  int       `json:"key_epoch"`
	SchemaVer int       `json:"schema_ver"`
	Deleted   bool      `json:"deleted"`
	Blob      *string   `json:"blob,omitempty"`
	Sig       *string   `json:"sig,omitempty"`
	AuthorID  string    `json:"author_id"`
	VersionID string    `json:"version_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ItemVersion is one entry of an item's encrypted history. Its blob decodes to a
// payload carrying `parent_ids`, so lineage is readable only on device — the
// server can order versions by seq but cannot see the graph.
type ItemVersion struct {
	VersionID string    `json:"version_id"`
	ItemID    string    `json:"item_id"`
	SpaceID   string    `json:"space_id"`
	Seq       int       `json:"seq"`
	BaseSeq   int       `json:"base_seq"`
	KeyEpoch  int       `json:"key_epoch"`
	SchemaVer int       `json:"schema_ver"`
	Deleted   bool      `json:"deleted"`
	Blob      *string   `json:"blob,omitempty"`
	Sig       *string   `json:"sig,omitempty"`
	AuthorID  string    `json:"author_id"`
	CreatedAt time.Time `json:"created_at"`
}

// dbItem is a row of `item`. Its id is composite — `item:[space, item]` — so the
// item's own uuid is the tail.
type dbItem struct {
	ID        *models.RecordID `json:"id"`
	Space     *models.RecordID `json:"space"`
	Seq       int              `json:"seq"`
	BaseSeq   int              `json:"base_seq"`
	KeyEpoch  int              `json:"key_epoch"`
	SchemaVer int              `json:"schema_ver"`
	Deleted   bool             `json:"deleted"`
	Blob      *string          `json:"blob"`
	Sig       *string          `json:"sig"`
	Author    *models.RecordID `json:"author"`
	Version   *models.RecordID `json:"version"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
}

func (r dbItem) toItem() *Item {
	return &Item{
		ID:        recordIDTail(r.ID),
		SpaceID:   recordIDString(r.Space),
		Seq:       r.Seq,
		BaseSeq:   r.BaseSeq,
		KeyEpoch:  r.KeyEpoch,
		SchemaVer: r.SchemaVer,
		Deleted:   r.Deleted,
		Blob:      r.Blob,
		Sig:       r.Sig,
		AuthorID:  recordIDString(r.Author),
		VersionID: recordIDTail(r.Version),
		CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
	}
}

// dbItemVersion is a row of `item_version`. Its id is `[space, item, version]`,
// and it reaches its parent through the scalar `item_id` uuid rather than a
// record link — SurrealDB cannot index a link whose target has an array id.
type dbItemVersion struct {
	ID        *models.RecordID `json:"id"`
	ItemID    models.UUID      `json:"item_id"`
	Space     *models.RecordID `json:"space"`
	Seq       int              `json:"seq"`
	BaseSeq   int              `json:"base_seq"`
	KeyEpoch  int              `json:"key_epoch"`
	SchemaVer int              `json:"schema_ver"`
	Deleted   bool             `json:"deleted"`
	Blob      *string          `json:"blob"`
	Sig       *string          `json:"sig"`
	Author    *models.RecordID `json:"author"`
	CreatedAt time.Time        `json:"created_at"`
}

func (r dbItemVersion) toVersion() *ItemVersion {
	return &ItemVersion{
		VersionID: recordIDTail(r.ID),
		ItemID:    r.ItemID.String(),
		SpaceID:   recordIDString(r.Space),
		Seq:       r.Seq,
		BaseSeq:   r.BaseSeq,
		KeyEpoch:  r.KeyEpoch,
		SchemaVer: r.SchemaVer,
		Deleted:   r.Deleted,
		Blob:      r.Blob,
		Sig:       r.Sig,
		AuthorID:  recordIDString(r.Author),
		CreatedAt: r.CreatedAt,
	}
}

// PushVersionParams is one client-authored version envelope. The client mints
// VersionID so the AAD can bind it before upload.
type PushVersionParams struct {
	VersionID string `json:"version_id"`
	Blob      string `json:"blob"`
	Sig       string `json:"sig"`
}

// PushItemParams is one envelope write. Versions carries the history entries this
// write appends: one for an ordinary edit, two for a conflict merge (the losing
// branch followed by the merge result). The last entry becomes the item's
// current version. A tombstone carries none.
type PushItemParams struct {
	// Client-chosen item UUID — the AAD binds it before upload.
	ItemID    string
	BaseSeq   int
	KeyEpoch  int
	SchemaVer int
	Deleted   bool
	Blob      string
	Sig       string
	Versions  []PushVersionParams
}

// PushOutcome reports one item write. Status is "ok", "conflict", "stale_epoch",
// or "forbidden". On conflict, Current carries the row the client must merge
// against; on stale_epoch, CurrentEpoch the epoch to re-wrap under.
type PushOutcome struct {
	ItemID       string `json:"item_id"`
	Status       string `json:"status"`
	Seq          int    `json:"seq,omitempty"`
	CurrentEpoch int    `json:"current_epoch,omitempty"`
	Current      *Item  `json:"current,omitempty"`
}

const pushTxnAttempts = 3

// pushStatement builds the push transaction. It serializes on the space row:
// `seq += 1` on space makes concurrent pushes to one space conflict at commit;
// the caller retries. Version rows are created from the client's payloads before
// the head is upserted.
//
// Every record id is bound as a parameter rather than built in the statement:
// SurrealDB 3.1.5 does not use an index for a predicate that constructs its own
// value, so `$item` stays an addressable key where
// `type::record('item', [<uuid>$s, <uuid>$i])` would degrade to a scan.
//
// The `version` assignment is omitted when the write carries no versions, so the
// head keeps pointing at its previous one (see apps/api/CLAUDE.md on optional
// fields).
func pushStatement(hasVersions bool) string {
	headAssignments := []string{
		"space = $space", "seq = $sp2.seq", "base_seq = $base_seq",
		"key_epoch = $key_epoch", "schema_ver = $schema_ver", "deleted = $deleted",
		"deleted_at = IF $deleted { time::now() } ELSE { NONE }",
		"blob = IF $deleted { NONE } ELSE { $blob }",
		"sig = $sig", "author = $user",
	}
	if hasVersions {
		headAssignments = append(headAssignments, "version = $head_version")
	}

	return `
	BEGIN TRANSACTION;
	LET $m = (SELECT * FROM space_member
		WHERE space = $space AND user = $user AND status = 'active'
		AND role IN ['owner', 'writer'] LIMIT 1)[0];
	LET $sp = (SELECT * FROM $space LIMIT 1)[0];
	LET $existing = (SELECT * FROM $item LIMIT 1)[0];
	LET $result = IF $m == NONE OR $sp == NONE {
		{ status: 'forbidden' }
	} ELSE IF $existing != NONE AND $existing.space != $space {
		{ status: 'forbidden' }
	} ELSE IF $sp.key_epoch != $key_epoch {
		{ status: 'stale_epoch', current_epoch: $sp.key_epoch }
	} ELSE IF ($existing == NONE AND $base_seq != 0)
		OR ($existing != NONE AND $existing.seq != $base_seq) {
		{ status: 'conflict', current: $existing }
	} ELSE {
		LET $sp2 = (UPDATE ONLY $space SET seq += 1 RETURN AFTER);
		FOR $v IN $versions {
			CREATE $v.ref SET
				item_id = $item_uuid, space = $space, seq = $sp2.seq,
				base_seq = $base_seq, key_epoch = $key_epoch,
				schema_ver = $schema_ver, deleted = $deleted,
				blob = $v.blob, sig = $v.sig, author = $user;
		};
		LET $row = (UPSERT ONLY $item SET ` + strings.Join(headAssignments, ", ") + `);
		{ status: 'ok', item: $row }
	};
	RETURN $result;
	COMMIT TRANSACTION;`
}

type dbPushResult struct {
	Status       string  `json:"status"`
	CurrentEpoch int     `json:"current_epoch"`
	Current      *dbItem `json:"current"`
	Item         *dbItem `json:"item"`
}

// PushItem writes one envelope plus its versions with optimistic concurrency on
// base_seq. Returns the outcome; ErrSpaceForbidden / ErrStaleEpoch /
// ErrSeqConflict are also reflected in the error for single-item callers.
func (s *SpaceStore) PushItem(ctx context.Context, spaceID, userID models.RecordID, p PushItemParams) (*PushOutcome, error) {
	refs, err := itemRefsFor(spaceID, p.ItemID, p.Versions)
	if err != nil {
		return nil, err
	}

	params := map[string]any{
		"space":      spaceID,
		"user":       userID,
		"item":       refs.item,
		"item_uuid":  refs.itemUUID,
		"base_seq":   p.BaseSeq,
		"key_epoch":  p.KeyEpoch,
		"schema_ver": p.SchemaVer,
		"deleted":    p.Deleted,
		"blob":       p.Blob,
		"sig":        p.Sig,
		"versions":   refs.versions,
	}
	if len(refs.versions) > 0 {
		params["head_version"] = refs.versions[len(refs.versions)-1]["ref"]
	}

	statement := pushStatement(len(p.Versions) > 0)

	var lastErr error
	for attempt := 0; attempt < pushTxnAttempts; attempt++ {
		results, err := surrealdb.Query[dbPushResult](ctx, s.DB, statement, params)
		if err != nil {
			if !isTxnConflict(err) {
				return nil, fmt.Errorf("push item: %w", err)
			}
			lastErr = err
			sleepWithJitter(attempt)
			continue
		}
		// A transaction yields one result per statement; only the RETURN carries data.
		for _, qr := range *results {
			if qr.Result.Status == "" {
				continue
			}
			return s.pushOutcome(p.ItemID, qr.Result)
		}
		return nil, fmt.Errorf("push item: empty result")
	}
	return nil, fmt.Errorf("push item: retries exhausted: %w", lastErr)
}

// itemRefs are the record ids one push addresses: the head, and one row per
// version. Both embed the space so its rows stay contiguous on disk; versions go
// one level deeper so an item's history sorts beside it.
type itemRefs struct {
	item     models.RecordID
	itemUUID models.UUID
	versions []map[string]any
}

func itemRefsFor(spaceID models.RecordID, itemID string, versions []PushVersionParams) (*itemRefs, error) {
	spaceUUID, err := recordUUID(&spaceID)
	if err != nil {
		return nil, fmt.Errorf("space id: %w", err)
	}
	itemUUID, err := parseUUID(itemID)
	if err != nil {
		return nil, fmt.Errorf("item id: %w", err)
	}

	rows := make([]map[string]any, 0, len(versions))
	for _, version := range versions {
		versionUUID, err := parseUUID(version.VersionID)
		if err != nil {
			return nil, fmt.Errorf("version id: %w", err)
		}
		rows = append(rows, map[string]any{
			"ref":  models.NewRecordID("item_version", []any{spaceUUID, itemUUID, versionUUID}),
			"blob": version.Blob,
			"sig":  version.Sig,
		})
	}

	return &itemRefs{
		item:     models.NewRecordID("item", []any{spaceUUID, itemUUID}),
		itemUUID: itemUUID,
		versions: rows,
	}, nil
}

func (s *SpaceStore) pushOutcome(itemID string, r dbPushResult) (*PushOutcome, error) {
	outcome := &PushOutcome{ItemID: itemID, Status: r.Status}
	switch r.Status {
	case "ok":
		if r.Item != nil {
			outcome.Seq = r.Item.Seq
		}
		return outcome, nil
	case "conflict":
		if r.Current != nil {
			outcome.Current = r.Current.toItem()
		}
		return outcome, ErrSeqConflict
	case "stale_epoch":
		outcome.CurrentEpoch = r.CurrentEpoch
		return outcome, ErrStaleEpoch
	default:
		return outcome, ErrSpaceForbidden
	}
}

// PushItems writes a batch, one transaction per item, so a single conflict
// doesn't fail the whole import. Per-item outcomes are returned in order.
func (s *SpaceStore) PushItems(ctx context.Context, spaceID, userID models.RecordID, items []PushItemParams) ([]*PushOutcome, error) {
	outcomes := make([]*PushOutcome, 0, len(items))
	for _, item := range items {
		outcome, err := s.PushItem(ctx, spaceID, userID, item)
		if outcome == nil {
			return nil, fmt.Errorf("push batch item %s: %w", item.ItemID, err)
		}
		outcomes = append(outcomes, outcome)
	}
	return outcomes, nil
}

// PullPage is one page of the per-space sync feed.
type PullPage struct {
	Items     []*Item `json:"items"`
	SpaceSeq  int     `json:"space_seq"`
	KeyEpoch  int     `json:"key_epoch"`
	NextSince int     `json:"next_since"`
	HasMore   bool    `json:"has_more"`
}

// PullItems returns items with seq > since, ordered by seq. Any active member
// may pull. staleOnly filters to rows below the current epoch (the lazy
// re-encrypt worklist). A cursor below the purge horizon returns ErrCursorPurged
// — the client must full-resync.
func (s *SpaceStore) PullItems(ctx context.Context, spaceID, userID models.RecordID, since, limit int, staleOnly bool) (*PullPage, error) {
	caller, err := s.member(ctx, spaceID, userID)
	if err != nil {
		return nil, err
	}
	if caller.Status != "active" {
		return nil, ErrSpaceForbidden
	}
	space, err := s.space(ctx, spaceID)
	if err != nil {
		return nil, err
	}
	if since < space.PurgeHorizon {
		return nil, ErrCursorPurged
	}

	conditions := "space = $space AND seq > $since"
	if staleOnly {
		conditions += " AND key_epoch < $current_epoch"
	}
	results, err := surrealdb.Query[[]dbItem](ctx, s.DB,
		"SELECT * FROM item WHERE "+conditions+" ORDER BY seq ASC LIMIT $limit",
		map[string]any{
			"space": spaceID, "since": since, "limit": limit,
			"current_epoch": space.KeyEpoch,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("pull items: %w", err)
	}

	page := &PullPage{
		Items:     []*Item{},
		SpaceSeq:  space.Seq,
		KeyEpoch:  space.KeyEpoch,
		NextSince: since,
	}
	for _, qr := range *results {
		for _, row := range qr.Result {
			page.Items = append(page.Items, row.toItem())
		}
	}
	if len(page.Items) > 0 {
		page.NextSince = page.Items[len(page.Items)-1].Seq
	}
	page.HasMore = len(page.Items) == limit && page.NextSince < space.Seq
	return page, nil
}

// GetItem returns one envelope; caller must be an active member of its space.
// The composite key addresses the row directly — the same item uuid under a
// different space is a different record, not a row this can reach.
func (s *SpaceStore) GetItem(ctx context.Context, spaceID, userID models.RecordID, itemID string) (*Item, error) {
	caller, err := s.member(ctx, spaceID, userID)
	if err != nil {
		return nil, err
	}
	if caller.Status != "active" {
		return nil, ErrSpaceForbidden
	}
	refs, err := itemRefsFor(spaceID, itemID, nil)
	if err != nil {
		return nil, err
	}
	results, err := surrealdb.Query[[]dbItem](ctx, s.DB,
		"SELECT * FROM $item LIMIT 1", map[string]any{"item": refs.item},
	)
	if err != nil {
		return nil, fmt.Errorf("get item: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0].toItem(), nil
		}
	}
	return nil, ErrNotFound
}

// ListItemVersions returns the encrypted history of one item, oldest first. A
// conflict merge writes two versions under one seq; their order within that seq
// is resolved on device from the decrypted parent_ids.
//
// The read is scoped to the space, not just the item uuid: ids are client-chosen
// and unique only within a space, so two spaces may hold the same uuid and must
// not see each other's history. The uuid is bound with LET before the predicate
// reads it — a cast written into the predicate plans as a scan of the whole
// history table.
func (s *SpaceStore) ListItemVersions(ctx context.Context, spaceID, userID models.RecordID, itemID string) ([]*ItemVersion, error) {
	if _, err := s.GetItem(ctx, spaceID, userID, itemID); err != nil {
		return nil, err
	}
	refs, err := itemRefsFor(spaceID, itemID, nil)
	if err != nil {
		return nil, err
	}
	results, err := surrealdb.Query[[]dbItemVersion](ctx, s.DB, `
		LET $iid = $item_uuid;
		SELECT * FROM item_version
		WHERE space = $space AND item_id = $iid
		ORDER BY seq ASC, created_at ASC`,
		map[string]any{"space": spaceID, "item_uuid": refs.itemUUID},
	)
	if err != nil {
		return nil, fmt.Errorf("list item versions: %w", err)
	}
	versions := []*ItemVersion{}
	for _, qr := range *results {
		for _, row := range qr.Result {
			versions = append(versions, row.toVersion())
		}
	}
	return versions, nil
}

// PurgeTombstones deletes tombstoned items older than the retention window
// across all spaces, together with their version history, and advances each
// space's purge horizon so stale cursors are told to full-resync. Returns the
// number of items purged.
func (s *SpaceStore) PurgeTombstones(ctx context.Context, olderThan time.Duration) (int, error) {
	type candidate struct {
		Space  *models.RecordID `json:"space"`
		MaxSeq int              `json:"max_seq"`
		Count  int              `json:"count"`
	}
	cutoff := time.Now().Add(-olderThan)
	results, err := surrealdb.Query[[]candidate](ctx, s.DB, `
		SELECT space, math::max(seq) AS max_seq, count() AS count FROM item
		WHERE deleted = true AND deleted_at != NONE AND deleted_at < $cutoff
		GROUP BY space`,
		map[string]any{"cutoff": cutoff},
	)
	if err != nil {
		return 0, fmt.Errorf("purge tombstones: scan: %w", err)
	}

	purged := 0
	for _, qr := range *results {
		for _, c := range qr.Result {
			if err := s.purgeSpaceTombstones(ctx, c.Space, cutoff, c.MaxSeq); err != nil {
				return purged, fmt.Errorf("purge tombstones: space %s: %w", recordIDString(c.Space), err)
			}
			purged += c.Count
		}
	}
	return purged, nil
}

// purgeSpaceTombstones drops one space's expired tombstones. The doomed rows are
// read first because history rows reference their item by uuid rather than by
// record link, so the delete needs those uuids and not the composite keys.
func (s *SpaceStore) purgeSpaceTombstones(ctx context.Context, space *models.RecordID, cutoff time.Time, maxSeq int) error {
	doomed, err := s.expiredTombstones(ctx, space, cutoff)
	if err != nil {
		return err
	}
	if len(doomed.refs) == 0 {
		return nil
	}

	_, err = surrealdb.Query[[]any](ctx, s.DB, `
		BEGIN TRANSACTION;
		DELETE item_version WHERE space = $space AND item_id IN $item_uuids;
		DELETE item WHERE id IN $item_refs;
		UPDATE $space SET purge_horizon = math::max([purge_horizon, $max_seq]);
		COMMIT TRANSACTION;`,
		map[string]any{
			"space":      space,
			"item_uuids": doomed.uuids,
			"item_refs":  doomed.refs,
			"max_seq":    maxSeq,
		},
	)
	return err
}

type doomedItems struct {
	refs  []models.RecordID
	uuids []models.UUID
}

func (s *SpaceStore) expiredTombstones(ctx context.Context, space *models.RecordID, cutoff time.Time) (*doomedItems, error) {
	results, err := surrealdb.Query[[]struct {
		ID *models.RecordID `json:"id"`
	}](ctx, s.DB, `
		SELECT id FROM item
		WHERE space = $space AND deleted = true
		AND deleted_at != NONE AND deleted_at < $cutoff`,
		map[string]any{"space": space, "cutoff": cutoff},
	)
	if err != nil {
		return nil, fmt.Errorf("scan space tombstones: %w", err)
	}

	doomed := &doomedItems{}
	for _, qr := range *results {
		for _, row := range qr.Result {
			itemUUID, err := parseUUID(recordIDTail(row.ID))
			if err != nil {
				return nil, fmt.Errorf("tombstone id: %w", err)
			}
			doomed.refs = append(doomed.refs, *row.ID)
			doomed.uuids = append(doomed.uuids, itemUUID)
		}
	}
	return doomed, nil
}

// isTxnConflict detects SurrealDB's optimistic-transaction commit failure, the
// only error class worth retrying on the push path.
func isTxnConflict(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "conflict") || strings.Contains(message, "failed to commit")
}

func sleepWithJitter(attempt int) {
	base := time.Duration(attempt+1) * 25 * time.Millisecond
	time.Sleep(base + time.Duration(rand.Intn(25))*time.Millisecond)
}
