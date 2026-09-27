package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/neoworks/auth/publicerr"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// Client-safe errors shared by the space and item stores. Handlers map
// them to HTTP statuses (403 / 409 / 409 / 410).
var (
	ErrSpaceForbidden = publicerr.New("forbidden")
	ErrStaleEpoch     = publicerr.New("stale key epoch")
	ErrSeqConflict    = publicerr.New("sequence conflict")
	ErrCursorPurged   = publicerr.New("cursor purged")
)

// SpaceStore manages spaces (the unit of E2EE sharing + sync) and their
// memberships. The server never sees key material in the clear: `wrapped_keys`
// entries are sealed to member scope public keys client-side.
type SpaceStore struct {
	DB *surrealdb.DB
}

type WrappedKey struct {
	Epoch      int    `json:"epoch"`
	WrappedKey string `json:"wrapped_key"`
	Signature  string `json:"signature"`
}

type Space struct {
	ID           string    `json:"space_id"`
	OwnerID      string    `json:"owner_id"`
	Collection   string    `json:"collection"`
	Kind         string    `json:"kind"`
	NameEnc      *string   `json:"name_enc,omitempty"`
	KeyEpoch     int       `json:"key_epoch"`
	Seq          int       `json:"seq"`
	PurgeHorizon int       `json:"purge_horizon"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type SpaceMember struct {
	UserID          string       `json:"user_id"`
	Role            string       `json:"role"`
	Status          string       `json:"status"`
	AddedByID       string       `json:"added_by_id"`
	WrappedKeys     []WrappedKey `json:"wrapped_keys,omitempty"`
	AcceptSignature *string      `json:"accept_signature,omitempty"`
	CreatedAt       time.Time    `json:"created_at"`
	UpdatedAt       time.Time    `json:"updated_at"`
}

// SpaceMembership is one caller-centric row: the space plus the caller's own
// membership (their wrapped keys, role, status).
type SpaceMembership struct {
	Space  Space       `json:"space"`
	Member SpaceMember `json:"member"`
}

// ── DB row shapes ─────────────────────────────────────────────────────────────

type dbSpace struct {
	ID           *models.RecordID `json:"id"`
	Owner        *models.RecordID `json:"owner"`
	Collection   string           `json:"collection"`
	Kind         string           `json:"kind"`
	NameEnc      *string          `json:"name_enc"`
	KeyEpoch     int              `json:"key_epoch"`
	Seq          int              `json:"seq"`
	PurgeHorizon int              `json:"purge_horizon"`
	CreatedAt    time.Time        `json:"created_at"`
	UpdatedAt    time.Time        `json:"updated_at"`
}

type dbSpaceMember struct {
	Space           *models.RecordID `json:"space"`
	User            *models.RecordID `json:"user"`
	Role            string           `json:"role"`
	Status          string           `json:"status"`
	AddedBy         *models.RecordID `json:"added_by"`
	WrappedKeys     []WrappedKey     `json:"wrapped_keys"`
	AcceptSignature *string          `json:"accept_signature"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

// dbMembershipRow is a space_member row with its space link FETCHed into an
// embedded object.
type dbMembershipRow struct {
	SpaceRow        dbSpace          `json:"space"`
	User            *models.RecordID `json:"user"`
	Role            string           `json:"role"`
	Status          string           `json:"status"`
	AddedBy         *models.RecordID `json:"added_by"`
	WrappedKeys     []WrappedKey     `json:"wrapped_keys"`
	AcceptSignature *string          `json:"accept_signature"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

func (r dbSpace) toSpace() Space {
	return Space{
		ID:           recordIDString(r.ID),
		OwnerID:      recordIDString(r.Owner),
		Collection:   r.Collection,
		Kind:         r.Kind,
		NameEnc:      r.NameEnc,
		KeyEpoch:     r.KeyEpoch,
		Seq:          r.Seq,
		PurgeHorizon: r.PurgeHorizon,
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
	}
}

func (r dbSpaceMember) toMember() SpaceMember {
	return SpaceMember{
		UserID:          recordIDString(r.User),
		Role:            r.Role,
		Status:          r.Status,
		AddedByID:       recordIDString(r.AddedBy),
		WrappedKeys:     r.WrappedKeys,
		AcceptSignature: r.AcceptSignature,
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
	}
}

// ── Create ────────────────────────────────────────────────────────────────────

type CreateSpaceParams struct {
	// Client-chosen space UUID — the wrap signature binds it before upload, and
	// every item id in the space embeds it.
	SpaceID    string
	Collection string
	Kind       string
	NameEnc    *string
	// Owner's self-wrap of the freshly minted space key (epoch 1).
	WrappedKey string
	Signature  string
}

// Create makes a space plus the owner's active membership in one transaction.
// Idempotent for kind == 'personal': a second call returns the existing personal
// space for (owner, collection) without touching it.
func (s *SpaceStore) Create(ctx context.Context, userID models.RecordID, p CreateSpaceParams) (*SpaceMembership, error) {
	spaceUUID, err := parseUUID(p.SpaceID)
	if err != nil {
		return nil, publicerr.New("space_id must be a uuid")
	}

	assignments := []string{
		"owner = $user", "collection = $collection", "kind = $kind",
	}
	params := map[string]any{
		"user":       userID,
		"space_uuid": spaceUUID,
		"collection": p.Collection,
		"kind":       p.Kind,
		"wrapped_keys": []WrappedKey{{
			Epoch:      1,
			WrappedKey: p.WrappedKey,
			Signature:  p.Signature,
		}},
	}
	if p.NameEnc != nil {
		assignments = append(assignments, "name_enc = $name_enc")
		params["name_enc"] = *p.NameEnc
	}

	query := `
		BEGIN TRANSACTION;
		LET $existing = (SELECT * FROM space
			WHERE owner = $user AND collection = $collection AND kind = 'personal'
			LIMIT 1)[0];
		LET $space = IF $kind == 'personal' AND $existing != NONE {
			$existing
		} ELSE {
			LET $created = (CREATE ONLY type::record('space', $space_uuid) SET ` + strings.Join(assignments, ", ") + `);
			CREATE ONLY space_member SET
				space = $created.id, user = $user, role = 'owner', status = 'active',
				added_by = $user, wrapped_keys = $wrapped_keys;
			$created
		};
		RETURN $space;
		COMMIT TRANSACTION;`

	results, err := surrealdb.Query[dbSpace](ctx, s.DB, query, params)
	if err != nil {
		return nil, fmt.Errorf("create space: %w", err)
	}
	// A transaction yields one result per statement; only the RETURN carries data.
	for _, qr := range *results {
		if qr.Result.ID == nil {
			continue
		}
		return s.membershipFor(ctx, *qr.Result.ID, userID)
	}
	return nil, fmt.Errorf("create space: empty result")
}

// Rename sets the space's client-encrypted display label. Owner only — the label
// is what members see, so changing it is an ownership act, not a per-member
// preference. The server stores the ciphertext and never learns the name.
func (s *SpaceStore) Rename(ctx context.Context, spaceID, callerID models.RecordID, nameEnc string) error {
	space, err := s.space(ctx, spaceID)
	if err != nil {
		return err
	}
	if recordIDString(space.Owner) != recordIDString(&callerID) {
		return ErrSpaceForbidden
	}
	_, err = surrealdb.Query[[]any](ctx, s.DB,
		"UPDATE $space SET name_enc = $name_enc",
		map[string]any{"space": spaceID, "name_enc": nameEnc},
	)
	if err != nil {
		return fmt.Errorf("rename space: %w", err)
	}
	return nil
}

// ── Reads ─────────────────────────────────────────────────────────────────────

// ListForUser returns every space the user is a member of (invited or active)
// for one collection, including the caller's own wrapped keys.
func (s *SpaceStore) ListForUser(ctx context.Context, userID models.RecordID, collection string) ([]*SpaceMembership, error) {
	results, err := surrealdb.Query[[]dbMembershipRow](ctx, s.DB, `
		SELECT * FROM space_member
		WHERE user = $user AND space.collection = $collection
		ORDER BY created_at ASC
		FETCH space`,
		map[string]any{"user": userID, "collection": collection},
	)
	if err != nil {
		return nil, fmt.Errorf("list spaces: %w", err)
	}
	out := []*SpaceMembership{}
	for _, qr := range *results {
		for _, row := range qr.Result {
			member := dbSpaceMember{
				User: row.User, Role: row.Role, Status: row.Status,
				AddedBy: row.AddedBy, WrappedKeys: row.WrappedKeys,
				AcceptSignature: row.AcceptSignature,
				CreatedAt:       row.CreatedAt, UpdatedAt: row.UpdatedAt,
			}
			out = append(out, &SpaceMembership{
				Space:  row.SpaceRow.toSpace(),
				Member: member.toMember(),
			})
		}
	}
	return out, nil
}

// SpaceDetail is a space plus its full member list. Wrapped keys are only
// populated on the caller's own member row — other members' wraps are theirs.
type SpaceDetail struct {
	Space   Space         `json:"space"`
	Members []SpaceMember `json:"members"`
}

// Get returns a space with its member list. Caller must be an active member.
func (s *SpaceStore) Get(ctx context.Context, spaceID, userID models.RecordID) (*SpaceDetail, error) {
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

	results, err := surrealdb.Query[[]dbSpaceMember](ctx, s.DB,
		"SELECT * FROM space_member WHERE space = $space ORDER BY created_at ASC",
		map[string]any{"space": spaceID},
	)
	if err != nil {
		return nil, fmt.Errorf("get space members: %w", err)
	}

	callerID := recordIDString(&userID)
	detail := &SpaceDetail{Space: space.toSpace()}
	for _, qr := range *results {
		for _, row := range qr.Result {
			member := row.toMember()
			if member.UserID != callerID {
				member.WrappedKeys = nil
			}
			detail.Members = append(detail.Members, member)
		}
	}
	return detail, nil
}

// ── Membership lifecycle ──────────────────────────────────────────────────────

type InviteParams struct {
	MemberID    models.RecordID
	Role        string
	WrappedKeys []WrappedKey
}

// InviteMember adds a member row in status 'invited'. Caller must be the space
// owner-role member. The wrap set must cover every epoch still referenced by
// live items up to the current one, so the invitee can read all history.
func (s *SpaceStore) InviteMember(ctx context.Context, spaceID, callerID models.RecordID, p InviteParams) (*SpaceMember, error) {
	if err := s.requireRole(ctx, spaceID, callerID, "owner"); err != nil {
		return nil, err
	}
	space, err := s.space(ctx, spaceID)
	if err != nil {
		return nil, err
	}
	minEpoch, err := s.MinLiveEpoch(ctx, spaceID, space.KeyEpoch)
	if err != nil {
		return nil, err
	}
	if err := checkEpochCoverage(p.WrappedKeys, minEpoch, space.KeyEpoch); err != nil {
		return nil, err
	}

	results, err := surrealdb.Query[dbSpaceMember](ctx, s.DB, `
		CREATE ONLY space_member SET
			space = $space, user = $member, role = $role, status = 'invited',
			added_by = $caller, wrapped_keys = $wrapped_keys`,
		map[string]any{
			"space": spaceID, "member": p.MemberID, "caller": callerID,
			"role": p.Role, "wrapped_keys": p.WrappedKeys,
		},
	)
	if err != nil {
		if strings.Contains(err.Error(), "idx_space_member_unique") {
			return nil, publicerr.New("already a member")
		}
		return nil, fmt.Errorf("invite member: %w", err)
	}
	for _, qr := range *results {
		member := qr.Result.toMember()
		return &member, nil
	}
	return nil, fmt.Errorf("invite member: empty result")
}

// Accept activates the caller's invited membership and records their pin
// re-signature over the wrapped key material.
func (s *SpaceStore) Accept(ctx context.Context, spaceID, userID models.RecordID, acceptSignature string) error {
	results, err := surrealdb.Query[[]dbSpaceMember](ctx, s.DB, `
		UPDATE space_member SET status = 'active', accept_signature = $sig
		WHERE space = $space AND user = $user AND status = 'invited'`,
		map[string]any{"space": spaceID, "user": userID, "sig": acceptSignature},
	)
	if err != nil {
		return fmt.Errorf("accept membership: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return nil
		}
	}
	return ErrNotFound
}

// RemoveMember deletes a membership. Allowed for the owner (removing others) or
// for a non-owner member removing themselves (leave). Returns the space's
// current key epoch — the caller's client must rotate immediately after.
func (s *SpaceStore) RemoveMember(ctx context.Context, spaceID, callerID, memberID models.RecordID) (int, error) {
	space, err := s.space(ctx, spaceID)
	if err != nil {
		return 0, err
	}

	target, err := s.member(ctx, spaceID, memberID)
	if err != nil {
		return 0, err
	}
	if target.Role == "owner" {
		return 0, publicerr.New("the owner cannot be removed")
	}

	selfLeave := recordIDString(&callerID) == recordIDString(&memberID)
	if !selfLeave {
		if err := s.requireRole(ctx, spaceID, callerID, "owner"); err != nil {
			return 0, err
		}
	}

	_, err = surrealdb.Query[[]any](ctx, s.DB,
		"DELETE space_member WHERE space = $space AND user = $member",
		map[string]any{"space": spaceID, "member": memberID},
	)
	if err != nil {
		return 0, fmt.Errorf("remove member: %w", err)
	}
	return space.KeyEpoch, nil
}

type RotateParams struct {
	ExpectedEpoch int
	// One rewrap per remaining member (active and invited), sealed to the new epoch.
	Rewrapped []MemberWrap
}

type MemberWrap struct {
	UserID     models.RecordID
	WrappedKey string
	Signature  string
}

// Rotate bumps the space key epoch and appends the new wrapped key to every
// remaining member. The expected-epoch assert makes concurrent rotations safe:
// the loser gets ErrStaleEpoch, refetches, retries. The rewrap set must cover
// exactly the current member set.
func (s *SpaceStore) Rotate(ctx context.Context, spaceID, callerID models.RecordID, p RotateParams) (int, error) {
	if err := s.requireRole(ctx, spaceID, callerID, "owner"); err != nil {
		return 0, err
	}
	if err := s.checkRotationCoverage(ctx, spaceID, p.Rewrapped); err != nil {
		return 0, err
	}

	wrapsByUser := make([]map[string]any, 0, len(p.Rewrapped))
	for _, w := range p.Rewrapped {
		wrapsByUser = append(wrapsByUser, map[string]any{
			"user":        w.UserID,
			"wrapped_key": w.WrappedKey,
			"signature":   w.Signature,
		})
	}

	type rotateResult struct {
		Status   string `json:"status"`
		NewEpoch int    `json:"new_epoch"`
	}
	results, err := surrealdb.Query[rotateResult](ctx, s.DB, `
		BEGIN TRANSACTION;
		LET $sp = (SELECT * FROM space WHERE id = $space LIMIT 1)[0];
		LET $result = IF $sp == NONE {
			{ status: 'forbidden', new_epoch: 0 }
		} ELSE IF $sp.key_epoch != $expected_epoch {
			{ status: 'stale_epoch', new_epoch: $sp.key_epoch }
		} ELSE {
			LET $sp2 = (UPDATE ONLY $space SET key_epoch += 1 RETURN AFTER);
			FOR $w IN $wraps {
				UPDATE space_member SET wrapped_keys += [{
					epoch: $sp2.key_epoch,
					wrapped_key: $w.wrapped_key,
					signature: $w.signature
				}] WHERE space = $space AND user = $w.user;
			};
			{ status: 'ok', new_epoch: $sp2.key_epoch }
		};
		RETURN $result;
		COMMIT TRANSACTION;`,
		map[string]any{
			"space": spaceID, "expected_epoch": p.ExpectedEpoch, "wraps": wrapsByUser,
		},
	)
	if err != nil {
		return 0, fmt.Errorf("rotate space key: %w", err)
	}
	// A transaction yields one result per statement; only the RETURN carries data.
	for _, qr := range *results {
		switch qr.Result.Status {
		case "":
			continue
		case "ok":
			return qr.Result.NewEpoch, nil
		case "stale_epoch":
			return qr.Result.NewEpoch, ErrStaleEpoch
		default:
			return 0, ErrSpaceForbidden
		}
	}
	return 0, fmt.Errorf("rotate space key: empty result")
}

// Delete removes a space with all items, versions, and memberships. Owner only;
// personal spaces cannot be deleted.
func (s *SpaceStore) Delete(ctx context.Context, spaceID, callerID models.RecordID) error {
	space, err := s.space(ctx, spaceID)
	if err != nil {
		return err
	}
	if recordIDString(space.Owner) != recordIDString(&callerID) {
		return ErrSpaceForbidden
	}
	if space.Kind == "personal" {
		return publicerr.New("personal spaces cannot be deleted")
	}

	_, err = surrealdb.Query[[]any](ctx, s.DB, `
		BEGIN TRANSACTION;
		DELETE item_version WHERE space = $space;
		DELETE item WHERE space = $space;
		DELETE space_member WHERE space = $space;
		DELETE $space;
		COMMIT TRANSACTION;`,
		map[string]any{"space": spaceID},
	)
	if err != nil {
		return fmt.Errorf("delete space: %w", err)
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// MinLiveEpoch returns the smallest key epoch still referenced by a live
// (non-tombstoned) item, or currentEpoch when the space has no live items.
func (s *SpaceStore) MinLiveEpoch(ctx context.Context, spaceID models.RecordID, currentEpoch int) (int, error) {
	// ORDER BY + LIMIT instead of math::min — aggregates decode as CBOR floats.
	results, err := surrealdb.Query[[]int](ctx, s.DB, `
		SELECT VALUE key_epoch FROM item
		WHERE space = $space AND deleted = false
		ORDER BY key_epoch ASC LIMIT 1`,
		map[string]any{"space": spaceID},
	)
	if err != nil {
		return 0, fmt.Errorf("min live epoch: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0], nil
		}
	}
	return currentEpoch, nil
}

func checkEpochCoverage(wraps []WrappedKey, minEpoch, currentEpoch int) error {
	covered := map[int]bool{}
	for _, w := range wraps {
		covered[w.Epoch] = true
	}
	for epoch := minEpoch; epoch <= currentEpoch; epoch++ {
		if !covered[epoch] {
			return publicerr.New(fmt.Sprintf("wrapped keys must cover epoch %d", epoch))
		}
	}
	return nil
}

// checkRotationCoverage verifies the rewrap set matches the current member set
// exactly — every remaining member gets the new key, nobody else does.
func (s *SpaceStore) checkRotationCoverage(ctx context.Context, spaceID models.RecordID, rewrapped []MemberWrap) error {
	results, err := surrealdb.Query[[]dbSpaceMember](ctx, s.DB,
		"SELECT user FROM space_member WHERE space = $space",
		map[string]any{"space": spaceID},
	)
	if err != nil {
		return fmt.Errorf("rotation coverage: %w", err)
	}

	memberIDs := map[string]bool{}
	for _, qr := range *results {
		for _, row := range qr.Result {
			memberIDs[recordIDString(row.User)] = true
		}
	}

	rewrapIDs := map[string]bool{}
	for _, w := range rewrapped {
		rewrapIDs[recordIDString(&w.UserID)] = true
	}

	if len(memberIDs) != len(rewrapIDs) {
		return publicerr.New("rewrap set must cover exactly the current members")
	}
	for id := range memberIDs {
		if !rewrapIDs[id] {
			return publicerr.New("rewrap set must cover exactly the current members")
		}
	}
	return nil
}

// Collection returns the collection a space holds, so a handler can check the
// caller's OAuth scope before it writes.
func (s *SpaceStore) Collection(ctx context.Context, spaceID models.RecordID) (string, error) {
	space, err := s.space(ctx, spaceID)
	if err != nil {
		return "", err
	}
	return space.Collection, nil
}

func (s *SpaceStore) space(ctx context.Context, spaceID models.RecordID) (*dbSpace, error) {
	results, err := surrealdb.Query[[]dbSpace](ctx, s.DB,
		"SELECT * FROM space WHERE id = $space LIMIT 1",
		map[string]any{"space": spaceID},
	)
	if err != nil {
		return nil, fmt.Errorf("get space: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, ErrNotFound
}

func (s *SpaceStore) member(ctx context.Context, spaceID, userID models.RecordID) (*dbSpaceMember, error) {
	results, err := surrealdb.Query[[]dbSpaceMember](ctx, s.DB,
		"SELECT * FROM space_member WHERE space = $space AND user = $user LIMIT 1",
		map[string]any{"space": spaceID, "user": userID},
	)
	if err != nil {
		return nil, fmt.Errorf("get member: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, ErrSpaceForbidden
}

// requireRole asserts the caller is an active member with the given role.
func (s *SpaceStore) requireRole(ctx context.Context, spaceID, userID models.RecordID, role string) error {
	member, err := s.member(ctx, spaceID, userID)
	if err != nil {
		return err
	}
	if member.Status != "active" || member.Role != role {
		return ErrSpaceForbidden
	}
	return nil
}

func (s *SpaceStore) membershipFor(ctx context.Context, spaceID, userID models.RecordID) (*SpaceMembership, error) {
	space, err := s.space(ctx, spaceID)
	if err != nil {
		return nil, err
	}
	member, err := s.member(ctx, spaceID, userID)
	if err != nil {
		return nil, err
	}
	return &SpaceMembership{Space: space.toSpace(), Member: member.toMember()}, nil
}
