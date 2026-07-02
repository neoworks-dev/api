package database

import (
	"context"
	"fmt"
	"time"

	"github.com/neoworks/auth/oauth"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// ── User / device lookups ────────────────────────────────────────────────────

// GetUserIDByEmail resolves an email to its account record id.
func (s *SurrealStore) GetUserIDByEmail(ctx context.Context, email string) (string, error) {
	results, err := surrealdb.Query[[]struct {
		ID models.RecordID `json:"id"`
	}](ctx, s.DB, "SELECT id FROM user WHERE email = $email LIMIT 1",
		map[string]any{"email": email})
	if err != nil {
		return "", fmt.Errorf("get user id by email: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return recordIDString(&qr.Result[0].ID), nil
		}
	}
	return "", ErrNotFound
}

// GetUserEmail returns the email for an account record id.
func (s *SurrealStore) GetUserEmail(ctx context.Context, userID string) (string, error) {
	results, err := surrealdb.Query[[]struct {
		Email string `json:"email"`
	}](ctx, s.DB, "SELECT email FROM user WHERE id = $id LIMIT 1",
		map[string]any{"id": models.NewRecordID("user", userID)})
	if err != nil {
		return "", fmt.Errorf("get user email: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0].Email, nil
		}
	}
	return "", ErrNotFound
}

// ListDevicePublicKeys returns the public keys of all of a user's devices, so a
// guardian's share can be sealed to each device they own.
func (s *SurrealStore) ListDevicePublicKeys(ctx context.Context, userID string) ([]string, error) {
	results, err := surrealdb.Query[[]struct {
		PublicKey string `json:"public_key"`
	}](ctx, s.DB, "SELECT public_key FROM device WHERE user = $user",
		map[string]any{"user": models.NewRecordID("user", userID)})
	if err != nil {
		return nil, fmt.Errorf("list device public keys: %w", err)
	}
	for _, qr := range *results {
		keys := make([]string, 0, len(qr.Result))
		for _, row := range qr.Result {
			keys = append(keys, row.PublicKey)
		}
		return keys, nil
	}
	return nil, nil
}

// ── Emergency contact configuration ──────────────────────────────────────────

type GuardianShareParams struct {
	Email          string
	GuardianUserID string
	Label          *string
	ShareIndex     int
	Shares         []SealedDeviceShare
}

type SealedDeviceShare struct {
	DevicePublicKey string
	SealedShare     string
}

type SaveEmergencyContactsParams struct {
	OwnerID          string
	SocialWrappedAMK string
	Threshold        int
	Total            int
	Contacts         []GuardianShareParams
}

// SaveEmergencyContacts replaces the owner's entire guardian set + sealed shares
// and records the social wrap. Replace-all keeps the Shamir split consistent:
// editing guardians always re-splits, so partial updates never apply.
func (s *SurrealStore) SaveEmergencyContacts(ctx context.Context, params *SaveEmergencyContactsParams) error {
	owner := models.NewRecordID("user", params.OwnerID)

	if _, err := surrealdb.Query[[]any](ctx, s.DB,
		`DELETE emergency_contact WHERE owner = $owner;
		 DELETE recovery_share WHERE owner = $owner`,
		map[string]any{"owner": owner}); err != nil {
		return fmt.Errorf("clear emergency contacts: %w", err)
	}

	for _, contact := range params.Contacts {
		guardian := models.NewRecordID("user", contact.GuardianUserID)
		fields := map[string]any{
			"owner":       owner,
			"guardian":    guardian,
			"email":       contact.Email,
			"share_index": contact.ShareIndex,
		}
		setOptional(fields, "label", contact.Label)
		if _, err := surrealdb.Create[oauth.EmergencyContact](ctx, s.DB, "emergency_contact", fields); err != nil {
			return fmt.Errorf("create emergency contact: %w", err)
		}
		for _, share := range contact.Shares {
			if _, err := surrealdb.Create[oauth.RecoveryShare](ctx, s.DB, "recovery_share", map[string]any{
				"owner":             owner,
				"guardian":          guardian,
				"share_index":       contact.ShareIndex,
				"device_public_key": share.DevicePublicKey,
				"sealed_share":      share.SealedShare,
			}); err != nil {
				return fmt.Errorf("create recovery share: %w", err)
			}
		}
	}

	if _, err := surrealdb.Query[[]any](ctx, s.DB,
		`UPDATE user_key SET social_wrapped_amk = $wrap, social_threshold = $k, social_total = $n
		 WHERE user = $owner`,
		map[string]any{
			"owner": owner,
			"wrap":  params.SocialWrappedAMK,
			"k":     params.Threshold,
			"n":     params.Total,
		}); err != nil {
		return fmt.Errorf("update social wrap: %w", err)
	}
	return nil
}

// ClearEmergencyContacts disables social recovery and removes all shares.
func (s *SurrealStore) ClearEmergencyContacts(ctx context.Context, ownerID string) error {
	owner := models.NewRecordID("user", ownerID)
	if _, err := surrealdb.Query[[]any](ctx, s.DB,
		`DELETE emergency_contact WHERE owner = $owner;
		 DELETE recovery_share WHERE owner = $owner;
		 UPDATE user_key SET social_wrapped_amk = NONE, social_threshold = NONE, social_total = NONE
		 WHERE user = $owner`,
		map[string]any{"owner": owner}); err != nil {
		return fmt.Errorf("clear emergency contacts: %w", err)
	}
	return nil
}

func (s *SurrealStore) ListEmergencyContacts(ctx context.Context, ownerID string) ([]*oauth.EmergencyContact, error) {
	return s.queryEmergencyContacts(ctx,
		"SELECT * FROM emergency_contact WHERE owner = $owner ORDER BY share_index ASC",
		map[string]any{"owner": models.NewRecordID("user", ownerID)})
}

func (s *SurrealStore) ListEmergencyContactsForGuardian(ctx context.Context, guardianID string) ([]*oauth.EmergencyContact, error) {
	return s.queryEmergencyContacts(ctx,
		"SELECT * FROM emergency_contact WHERE guardian = $guardian",
		map[string]any{"guardian": models.NewRecordID("user", guardianID)})
}

func (s *SurrealStore) queryEmergencyContacts(ctx context.Context, query string, vars map[string]any) ([]*oauth.EmergencyContact, error) {
	results, err := surrealdb.Query[[]oauth.EmergencyContact](ctx, s.DB, query, vars)
	if err != nil {
		return nil, fmt.Errorf("query emergency contacts: %w", err)
	}
	for _, qr := range *results {
		out := make([]*oauth.EmergencyContact, len(qr.Result))
		for i := range qr.Result {
			out[i] = &qr.Result[i]
		}
		return out, nil
	}
	return nil, nil
}

// GetRecoverySharesForGuardian returns the sealed shares a guardian holds for an
// owner — one per guardian device. The guardian opens whichever matches a device
// keypair it has, then re-seals the plaintext share to the recovering device.
func (s *SurrealStore) GetRecoverySharesForGuardian(ctx context.Context, ownerID, guardianID string) ([]*oauth.RecoveryShare, error) {
	results, err := surrealdb.Query[[]oauth.RecoveryShare](ctx, s.DB,
		"SELECT * FROM recovery_share WHERE owner = $owner AND guardian = $guardian",
		map[string]any{
			"owner":    models.NewRecordID("user", ownerID),
			"guardian": models.NewRecordID("user", guardianID),
		})
	if err != nil {
		return nil, fmt.Errorf("get recovery shares for guardian: %w", err)
	}
	for _, qr := range *results {
		out := make([]*oauth.RecoveryShare, len(qr.Result))
		for i := range qr.Result {
			out[i] = &qr.Result[i]
		}
		return out, nil
	}
	return nil, nil
}

// IsGuardianOf reports whether guardianID is a designated guardian of ownerID.
func (s *SurrealStore) IsGuardianOf(ctx context.Context, ownerID, guardianID string) (bool, error) {
	results, err := surrealdb.Query[[]struct {
		ShareIndex int `json:"share_index"`
	}](ctx, s.DB,
		"SELECT share_index FROM emergency_contact WHERE owner = $owner AND guardian = $guardian LIMIT 1",
		map[string]any{
			"owner":    models.NewRecordID("user", ownerID),
			"guardian": models.NewRecordID("user", guardianID),
		})
	if err != nil {
		return false, fmt.Errorf("is guardian of: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return true, nil
		}
	}
	return false, nil
}

func (s *SurrealStore) GetGuardianShareIndex(ctx context.Context, ownerID, guardianID string) (int, error) {
	results, err := surrealdb.Query[[]struct {
		ShareIndex int `json:"share_index"`
	}](ctx, s.DB,
		"SELECT share_index FROM emergency_contact WHERE owner = $owner AND guardian = $guardian LIMIT 1",
		map[string]any{
			"owner":    models.NewRecordID("user", ownerID),
			"guardian": models.NewRecordID("user", guardianID),
		})
	if err != nil {
		return 0, fmt.Errorf("get guardian share index: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0].ShareIndex, nil
		}
	}
	return 0, ErrNotFound
}

// ── Recovery sessions ────────────────────────────────────────────────────────

func (s *SurrealStore) CreateRecoverySession(ctx context.Context, ownerID, recoveringPublicKey string, threshold int, expiresAt time.Time) (*oauth.RecoverySession, error) {
	result, err := surrealdb.Create[oauth.RecoverySession](ctx, s.DB, "recovery_session", map[string]any{
		"owner":                 models.NewRecordID("user", ownerID),
		"recovering_public_key": recoveringPublicKey,
		"threshold":             threshold,
		"status":                "pending",
		"expires_at":            expiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("create recovery session: %w", err)
	}
	return result, nil
}

func (s *SurrealStore) GetRecoverySession(ctx context.Context, ownerID, id string) (*oauth.RecoverySession, error) {
	return s.getRecoverySession(ctx,
		"SELECT * FROM recovery_session WHERE id = $id AND owner = $owner LIMIT 1",
		map[string]any{
			"id":    models.NewRecordID("recovery_session", id),
			"owner": models.NewRecordID("user", ownerID),
		})
}

func (s *SurrealStore) GetRecoverySessionByID(ctx context.Context, id string) (*oauth.RecoverySession, error) {
	return s.getRecoverySession(ctx,
		"SELECT * FROM recovery_session WHERE id = $id LIMIT 1",
		map[string]any{"id": models.NewRecordID("recovery_session", id)})
}

// GetActiveRecoverySession returns the owner's most recent non-expired pending
// session, or ErrNotFound.
func (s *SurrealStore) GetActiveRecoverySession(ctx context.Context, ownerID string) (*oauth.RecoverySession, error) {
	return s.getRecoverySession(ctx,
		`SELECT * FROM recovery_session
		 WHERE owner = $owner AND status = "pending" AND expires_at > time::now()
		 ORDER BY created_at DESC LIMIT 1`,
		map[string]any{"owner": models.NewRecordID("user", ownerID)})
}

func (s *SurrealStore) getRecoverySession(ctx context.Context, query string, vars map[string]any) (*oauth.RecoverySession, error) {
	results, err := surrealdb.Query[[]oauth.RecoverySession](ctx, s.DB, query, vars)
	if err != nil {
		return nil, fmt.Errorf("get recovery session: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, ErrNotFound
}

func (s *SurrealStore) CompleteRecoverySession(ctx context.Context, ownerID, id string) error {
	_, err := surrealdb.Query[[]any](ctx, s.DB,
		`UPDATE recovery_session SET status = "completed"
		 WHERE id = $id AND owner = $owner`,
		map[string]any{
			"id":    models.NewRecordID("recovery_session", id),
			"owner": models.NewRecordID("user", ownerID),
		})
	if err != nil {
		return fmt.Errorf("complete recovery session: %w", err)
	}
	return nil
}

// SubmitRecoverySessionShare stores a guardian's re-sealed share for a session,
// one per guardian (idempotent via the unique session+guardian index).
func (s *SurrealStore) SubmitRecoverySessionShare(ctx context.Context, sessionID, guardianID string, shareIndex int, sealedShare string) error {
	_, err := surrealdb.Query[[]any](ctx, s.DB,
		`UPSERT recovery_session_share
		 SET session = $session, guardian = $guardian, share_index = $idx, sealed_share = $share
		 WHERE session = $session AND guardian = $guardian`,
		map[string]any{
			"session":  models.NewRecordID("recovery_session", sessionID),
			"guardian": models.NewRecordID("user", guardianID),
			"idx":      shareIndex,
			"share":    sealedShare,
		})
	if err != nil {
		return fmt.Errorf("submit recovery session share: %w", err)
	}
	return nil
}

func (s *SurrealStore) ListRecoverySessionShares(ctx context.Context, sessionID string) ([]*oauth.RecoverySessionShare, error) {
	results, err := surrealdb.Query[[]oauth.RecoverySessionShare](ctx, s.DB,
		"SELECT * FROM recovery_session_share WHERE session = $session ORDER BY share_index ASC",
		map[string]any{"session": models.NewRecordID("recovery_session", sessionID)})
	if err != nil {
		return nil, fmt.Errorf("list recovery session shares: %w", err)
	}
	for _, qr := range *results {
		out := make([]*oauth.RecoverySessionShare, len(qr.Result))
		for i := range qr.Result {
			out[i] = &qr.Result[i]
		}
		return out, nil
	}
	return nil, nil
}

func (s *SurrealStore) HasSubmittedShare(ctx context.Context, sessionID, guardianID string) (bool, error) {
	results, err := surrealdb.Query[[]struct {
		ShareIndex int `json:"share_index"`
	}](ctx, s.DB,
		"SELECT share_index FROM recovery_session_share WHERE session = $session AND guardian = $guardian LIMIT 1",
		map[string]any{
			"session":  models.NewRecordID("recovery_session", sessionID),
			"guardian": models.NewRecordID("user", guardianID),
		})
	if err != nil {
		return false, fmt.Errorf("has submitted share: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return true, nil
		}
	}
	return false, nil
}
