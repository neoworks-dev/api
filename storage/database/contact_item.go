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

// ContactItem is one encrypted contact envelope. The server never sees the
// content — `Blob` is ciphertext, `Sig` the author's Ed25519 signature.
type ContactItem struct {
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
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type dbContactItem struct {
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
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
}

func (r dbContactItem) toItem() *ContactItem {
	return &ContactItem{
		ID:        recordIDString(r.ID),
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
		UpdatedAt: r.UpdatedAt,
	}
}

type PushItemParams struct {
	// Client-chosen item UUID — the AAD binds it before upload.
	ItemID    string
	BaseSeq   int
	KeyEpoch  int
	SchemaVer int
	Deleted   bool
	Blob      string
	Sig       string
}

// PushOutcome reports one item write. Status is "ok", "conflict",
// "stale_epoch", or "forbidden". On conflict, Current carries the row the
// client must merge against; on stale_epoch, CurrentEpoch the epoch to re-wrap
// under.
type PushOutcome struct {
	ItemID       string       `json:"item_id"`
	Status       string       `json:"status"`
	Seq          int          `json:"seq,omitempty"`
	CurrentEpoch int          `json:"current_epoch,omitempty"`
	Current      *ContactItem `json:"current,omitempty"`
}

const pushTxnAttempts = 3

// pushTxn serializes on the space row: `seq += 1` on space makes concurrent
// pushes to one space conflict at commit; the caller retries. The pre-update row
// is copied into contact_item_version first (append-only encrypted history), and
// tombstoning drops the ciphertext.
const pushTxn = `
	BEGIN TRANSACTION;
	LET $m = (SELECT * FROM space_member
		WHERE space = $space AND user = $user AND status = 'active'
		AND role IN ['owner', 'writer'] LIMIT 1)[0];
	LET $sp = (SELECT * FROM space WHERE id = $space LIMIT 1)[0];
	LET $existing = (SELECT * FROM contact_item WHERE id = $item LIMIT 1)[0];
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
		IF $existing != NONE {
			CREATE contact_item_version SET
				item = $existing.id, space = $existing.space, seq = $existing.seq,
				base_seq = $existing.base_seq, key_epoch = $existing.key_epoch,
				schema_ver = $existing.schema_ver, deleted = $existing.deleted,
				blob = $existing.blob, sig = $existing.sig,
				author = $existing.author, item_created_at = $existing.created_at;
		};
		LET $sp2 = (UPDATE ONLY $space SET seq += 1 RETURN AFTER);
		LET $row = (UPSERT ONLY type::record('contact_item', $item_uuid) SET
			space = $space, seq = $sp2.seq, base_seq = $base_seq,
			key_epoch = $key_epoch, schema_ver = $schema_ver, deleted = $deleted,
			deleted_at = IF $deleted { time::now() } ELSE { NONE },
			blob = IF $deleted { NONE } ELSE { $blob },
			sig = $sig, author = $user);
		{ status: 'ok', item: $row }
	};
	RETURN $result;
	COMMIT TRANSACTION;`

type dbPushResult struct {
	Status       string         `json:"status"`
	CurrentEpoch int            `json:"current_epoch"`
	Current      *dbContactItem `json:"current"`
	Item         *dbContactItem `json:"item"`
}

// PushItem writes one envelope with optimistic concurrency on base_seq.
// Returns the outcome; ErrSpaceForbidden / ErrStaleEpoch / ErrSeqConflict are
// also reflected in the error for single-item callers.
func (s *SpaceStore) PushItem(ctx context.Context, spaceID, userID models.RecordID, p PushItemParams) (*PushOutcome, error) {
	params := map[string]any{
		"space":      spaceID,
		"user":       userID,
		"item":       models.NewRecordID("contact_item", p.ItemID),
		"item_uuid":  p.ItemID,
		"base_seq":   p.BaseSeq,
		"key_epoch":  p.KeyEpoch,
		"schema_ver": p.SchemaVer,
		"deleted":    p.Deleted,
		"blob":       p.Blob,
		"sig":        p.Sig,
	}

	var lastErr error
	for attempt := 0; attempt < pushTxnAttempts; attempt++ {
		results, err := surrealdb.Query[dbPushResult](ctx, s.DB, pushTxn, params)
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
	Items     []*ContactItem `json:"items"`
	SpaceSeq  int            `json:"space_seq"`
	KeyEpoch  int            `json:"key_epoch"`
	NextSince int            `json:"next_since"`
	HasMore   bool           `json:"has_more"`
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
	results, err := surrealdb.Query[[]dbContactItem](ctx, s.DB,
		"SELECT * FROM contact_item WHERE "+conditions+" ORDER BY seq ASC LIMIT $limit",
		map[string]any{
			"space": spaceID, "since": since, "limit": limit,
			"current_epoch": space.KeyEpoch,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("pull items: %w", err)
	}

	page := &PullPage{
		Items:     []*ContactItem{},
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
func (s *SpaceStore) GetItem(ctx context.Context, spaceID, userID models.RecordID, itemID string) (*ContactItem, error) {
	caller, err := s.member(ctx, spaceID, userID)
	if err != nil {
		return nil, err
	}
	if caller.Status != "active" {
		return nil, ErrSpaceForbidden
	}
	results, err := surrealdb.Query[[]dbContactItem](ctx, s.DB,
		"SELECT * FROM contact_item WHERE id = $item AND space = $space LIMIT 1",
		map[string]any{
			"item":  models.NewRecordID("contact_item", itemID),
			"space": spaceID,
		},
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

// ListItemVersions returns the encrypted history of one item, oldest first.
func (s *SpaceStore) ListItemVersions(ctx context.Context, spaceID, userID models.RecordID, itemID string) ([]*ContactItem, error) {
	if _, err := s.GetItem(ctx, spaceID, userID, itemID); err != nil {
		return nil, err
	}
	results, err := surrealdb.Query[[]dbContactItem](ctx, s.DB,
		"SELECT * FROM contact_item_version WHERE item = $item ORDER BY seq ASC",
		map[string]any{"item": models.NewRecordID("contact_item", itemID)},
	)
	if err != nil {
		return nil, fmt.Errorf("list item versions: %w", err)
	}
	versions := []*ContactItem{}
	for _, qr := range *results {
		for _, row := range qr.Result {
			item := row.toItem()
			item.ID = itemID
			versions = append(versions, item)
		}
	}
	return versions, nil
}

// PurgeTombstones deletes tombstoned envelopes older than the retention window
// across all spaces and advances each space's purge horizon so stale cursors
// are told to full-resync. Returns the number of rows purged.
func (s *SpaceStore) PurgeTombstones(ctx context.Context, olderThan time.Duration) (int, error) {
	type candidate struct {
		Space  *models.RecordID `json:"space"`
		MaxSeq int              `json:"max_seq"`
		Count  int              `json:"count"`
	}
	cutoff := time.Now().Add(-olderThan)
	results, err := surrealdb.Query[[]candidate](ctx, s.DB, `
		SELECT space, math::max(seq) AS max_seq, count() AS count FROM contact_item
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
			_, err := surrealdb.Query[[]any](ctx, s.DB, `
				BEGIN TRANSACTION;
				DELETE contact_item WHERE space = $space AND deleted = true AND deleted_at != NONE AND deleted_at < $cutoff;
				UPDATE $space SET purge_horizon = math::max([purge_horizon, $max_seq]);
				COMMIT TRANSACTION;`,
				map[string]any{"space": c.Space, "cutoff": cutoff, "max_seq": c.MaxSeq},
			)
			if err != nil {
				return purged, fmt.Errorf("purge tombstones: space %s: %w", recordIDString(c.Space), err)
			}
			purged += c.Count
		}
	}
	return purged, nil
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
