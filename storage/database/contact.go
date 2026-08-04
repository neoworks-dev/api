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

// Contact is one encrypted contact envelope. The server never sees the content —
// `Blob` is ciphertext, `Sig` the author's Ed25519 signature. `VersionID` names
// the version row holding this contact's current content.
type Contact struct {
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

// ContactVersion is one entry of a contact's encrypted history. Its blob decodes
// to a ContactVersion payload carrying `parent_ids`, so lineage is readable only
// on device — the server can order versions by seq but cannot see the graph.
type ContactVersion struct {
	VersionID string    `json:"version_id"`
	ContactID string    `json:"item_id"`
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

type dbContact struct {
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

func (r dbContact) toContact() *Contact {
	return &Contact{
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
		VersionID: recordIDString(r.Version),
		CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
	}
}

type dbContactVersion struct {
	ID        *models.RecordID `json:"id"`
	Contact   *models.RecordID `json:"contact"`
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

func (r dbContactVersion) toVersion() *ContactVersion {
	return &ContactVersion{
		VersionID: recordIDString(r.ID),
		ContactID: recordIDString(r.Contact),
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

// PushContactParams is one envelope write. Versions carries the history entries
// this write appends: one for an ordinary edit, two for a conflict merge (the
// losing branch followed by the merge result). The last entry becomes the
// contact's current version. A tombstone carries none.
type PushContactParams struct {
	// Client-chosen contact UUID — the AAD binds it before upload.
	ContactID string
	BaseSeq   int
	KeyEpoch  int
	SchemaVer int
	Deleted   bool
	Blob      string
	Sig       string
	Versions  []PushVersionParams
}

// PushOutcome reports one contact write. Status is "ok", "conflict",
// "stale_epoch", or "forbidden". On conflict, Current carries the row the
// client must merge against; on stale_epoch, CurrentEpoch the epoch to re-wrap
// under.
type PushOutcome struct {
	ContactID    string   `json:"item_id"`
	Status       string   `json:"status"`
	Seq          int      `json:"seq,omitempty"`
	CurrentEpoch int      `json:"current_epoch,omitempty"`
	Current      *Contact `json:"current,omitempty"`
}

const pushTxnAttempts = 3

// pushStatement builds the push transaction. It serializes on the space row:
// `seq += 1` on space makes concurrent pushes to one space conflict at commit;
// the caller retries. Version rows are created from the client's payloads before
// the head is upserted.
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
		headAssignments = append(headAssignments,
			"version = type::record('contact_version', $head_version)")
	}

	return `
	BEGIN TRANSACTION;
	LET $m = (SELECT * FROM space_member
		WHERE space = $space AND user = $user AND status = 'active'
		AND role IN ['owner', 'writer'] LIMIT 1)[0];
	LET $sp = (SELECT * FROM space WHERE id = $space LIMIT 1)[0];
	LET $existing = (SELECT * FROM contact WHERE id = $contact LIMIT 1)[0];
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
			CREATE type::record('contact_version', $v.version_id) SET
				contact = $contact, space = $space, seq = $sp2.seq,
				base_seq = $base_seq, key_epoch = $key_epoch,
				schema_ver = $schema_ver, deleted = $deleted,
				blob = $v.blob, sig = $v.sig, author = $user;
		};
		LET $row = (UPSERT ONLY type::record('contact', $contact_uuid) SET ` +
		strings.Join(headAssignments, ", ") + `);
		{ status: 'ok', item: $row }
	};
	RETURN $result;
	COMMIT TRANSACTION;`
}

type dbPushResult struct {
	Status       string     `json:"status"`
	CurrentEpoch int        `json:"current_epoch"`
	Current      *dbContact `json:"current"`
	Item         *dbContact `json:"item"`
}

// PushContact writes one envelope plus its versions with optimistic concurrency
// on base_seq. Returns the outcome; ErrSpaceForbidden / ErrStaleEpoch /
// ErrSeqConflict are also reflected in the error for single-item callers.
func (s *SpaceStore) PushContact(ctx context.Context, spaceID, userID models.RecordID, p PushContactParams) (*PushOutcome, error) {
	params := map[string]any{
		"space":        spaceID,
		"user":         userID,
		"contact":      models.NewRecordID("contact", p.ContactID),
		"contact_uuid": p.ContactID,
		"base_seq":     p.BaseSeq,
		"key_epoch":    p.KeyEpoch,
		"schema_ver":   p.SchemaVer,
		"deleted":      p.Deleted,
		"blob":         p.Blob,
		"sig":          p.Sig,
		"versions":     versionRows(p.Versions),
	}
	if len(p.Versions) > 0 {
		params["head_version"] = p.Versions[len(p.Versions)-1].VersionID
	}

	statement := pushStatement(len(p.Versions) > 0)

	var lastErr error
	for attempt := 0; attempt < pushTxnAttempts; attempt++ {
		results, err := surrealdb.Query[dbPushResult](ctx, s.DB, statement, params)
		if err != nil {
			if !isTxnConflict(err) {
				return nil, fmt.Errorf("push contact: %w", err)
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
			return s.pushOutcome(p.ContactID, qr.Result)
		}
		return nil, fmt.Errorf("push contact: empty result")
	}
	return nil, fmt.Errorf("push contact: retries exhausted: %w", lastErr)
}

func versionRows(versions []PushVersionParams) []map[string]any {
	rows := make([]map[string]any, 0, len(versions))
	for _, v := range versions {
		rows = append(rows, map[string]any{
			"version_id": v.VersionID,
			"blob":       v.Blob,
			"sig":        v.Sig,
		})
	}
	return rows
}

func (s *SpaceStore) pushOutcome(contactID string, r dbPushResult) (*PushOutcome, error) {
	outcome := &PushOutcome{ContactID: contactID, Status: r.Status}
	switch r.Status {
	case "ok":
		if r.Item != nil {
			outcome.Seq = r.Item.Seq
		}
		return outcome, nil
	case "conflict":
		if r.Current != nil {
			outcome.Current = r.Current.toContact()
		}
		return outcome, ErrSeqConflict
	case "stale_epoch":
		outcome.CurrentEpoch = r.CurrentEpoch
		return outcome, ErrStaleEpoch
	default:
		return outcome, ErrSpaceForbidden
	}
}

// PushContacts writes a batch, one transaction per contact, so a single conflict
// doesn't fail the whole import. Per-item outcomes are returned in order.
func (s *SpaceStore) PushContacts(ctx context.Context, spaceID, userID models.RecordID, contacts []PushContactParams) ([]*PushOutcome, error) {
	outcomes := make([]*PushOutcome, 0, len(contacts))
	for _, contact := range contacts {
		outcome, err := s.PushContact(ctx, spaceID, userID, contact)
		if outcome == nil {
			return nil, fmt.Errorf("push batch item %s: %w", contact.ContactID, err)
		}
		outcomes = append(outcomes, outcome)
	}
	return outcomes, nil
}

// PullPage is one page of the per-space sync feed.
type PullPage struct {
	Items     []*Contact `json:"items"`
	SpaceSeq  int        `json:"space_seq"`
	KeyEpoch  int        `json:"key_epoch"`
	NextSince int        `json:"next_since"`
	HasMore   bool       `json:"has_more"`
}

// PullContacts returns contacts with seq > since, ordered by seq. Any active
// member may pull. staleOnly filters to rows below the current epoch (the lazy
// re-encrypt worklist). A cursor below the purge horizon returns ErrCursorPurged
// — the client must full-resync.
func (s *SpaceStore) PullContacts(ctx context.Context, spaceID, userID models.RecordID, since, limit int, staleOnly bool) (*PullPage, error) {
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
	results, err := surrealdb.Query[[]dbContact](ctx, s.DB,
		"SELECT * FROM contact WHERE "+conditions+" ORDER BY seq ASC LIMIT $limit",
		map[string]any{
			"space": spaceID, "since": since, "limit": limit,
			"current_epoch": space.KeyEpoch,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("pull contacts: %w", err)
	}

	page := &PullPage{
		Items:     []*Contact{},
		SpaceSeq:  space.Seq,
		KeyEpoch:  space.KeyEpoch,
		NextSince: since,
	}
	for _, qr := range *results {
		for _, row := range qr.Result {
			page.Items = append(page.Items, row.toContact())
		}
	}
	if len(page.Items) > 0 {
		page.NextSince = page.Items[len(page.Items)-1].Seq
	}
	page.HasMore = len(page.Items) == limit && page.NextSince < space.Seq
	return page, nil
}

// GetContact returns one envelope; caller must be an active member of its space.
func (s *SpaceStore) GetContact(ctx context.Context, spaceID, userID models.RecordID, contactID string) (*Contact, error) {
	caller, err := s.member(ctx, spaceID, userID)
	if err != nil {
		return nil, err
	}
	if caller.Status != "active" {
		return nil, ErrSpaceForbidden
	}
	results, err := surrealdb.Query[[]dbContact](ctx, s.DB,
		"SELECT * FROM contact WHERE id = $contact AND space = $space LIMIT 1",
		map[string]any{
			"contact": models.NewRecordID("contact", contactID),
			"space":   spaceID,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("get contact: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0].toContact(), nil
		}
	}
	return nil, ErrNotFound
}

// ListContactVersions returns the encrypted history of one contact, oldest
// first. A conflict merge writes two versions under one seq; their order within
// that seq is resolved on device from the decrypted parent_ids.
func (s *SpaceStore) ListContactVersions(ctx context.Context, spaceID, userID models.RecordID, contactID string) ([]*ContactVersion, error) {
	if _, err := s.GetContact(ctx, spaceID, userID, contactID); err != nil {
		return nil, err
	}
	results, err := surrealdb.Query[[]dbContactVersion](ctx, s.DB,
		"SELECT * FROM contact_version WHERE contact = $contact ORDER BY seq ASC, created_at ASC",
		map[string]any{"contact": models.NewRecordID("contact", contactID)},
	)
	if err != nil {
		return nil, fmt.Errorf("list contact versions: %w", err)
	}
	versions := []*ContactVersion{}
	for _, qr := range *results {
		for _, row := range qr.Result {
			versions = append(versions, row.toVersion())
		}
	}
	return versions, nil
}

// PurgeTombstones deletes tombstoned contacts older than the retention window
// across all spaces, together with their version history, and advances each
// space's purge horizon so stale cursors are told to full-resync. Returns the
// number of contacts purged.
func (s *SpaceStore) PurgeTombstones(ctx context.Context, olderThan time.Duration) (int, error) {
	type candidate struct {
		Space  *models.RecordID `json:"space"`
		MaxSeq int              `json:"max_seq"`
		Count  int              `json:"count"`
	}
	cutoff := time.Now().Add(-olderThan)
	results, err := surrealdb.Query[[]candidate](ctx, s.DB, `
		SELECT space, math::max(seq) AS max_seq, count() AS count FROM contact
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

func (s *SpaceStore) purgeSpaceTombstones(ctx context.Context, space *models.RecordID, cutoff time.Time, maxSeq int) error {
	_, err := surrealdb.Query[[]any](ctx, s.DB, `
		BEGIN TRANSACTION;
		LET $doomed = (SELECT VALUE id FROM contact
			WHERE space = $space AND deleted = true
			AND deleted_at != NONE AND deleted_at < $cutoff);
		DELETE contact_version WHERE contact IN $doomed;
		DELETE contact WHERE id IN $doomed;
		UPDATE $space SET purge_horizon = math::max([purge_horizon, $max_seq]);
		COMMIT TRANSACTION;`,
		map[string]any{"space": space, "cutoff": cutoff, "max_seq": maxSeq},
	)
	return err
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
