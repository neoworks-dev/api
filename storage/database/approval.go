package database

import (
	"context"
	"fmt"
	"time"

	"github.com/neoworks/auth/oauth"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

type CreateApprovalParams struct {
	UserID              string
	Type                string // signin | token_refresh
	Client              string
	Scopes              []string
	RequestingLabel     *string
	RequestingUserAgent *string
	IP                  *string
	Location            *string
	LoginChallenge      *string
	ExpiresAt           time.Time
}

func (s *SurrealStore) CreateApprovalRequest(ctx context.Context, params *CreateApprovalParams) (*oauth.ApprovalRequest, error) {
	scopes := params.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	fields := map[string]any{
		"user":       models.NewRecordID("user", params.UserID),
		"type":       params.Type,
		"client":     params.Client,
		"scopes":     scopes,
		"expires_at": params.ExpiresAt,
	}
	setOptional(fields, "requesting_label", params.RequestingLabel)
	setOptional(fields, "requesting_user_agent", params.RequestingUserAgent)
	setOptional(fields, "ip", params.IP)
	setOptional(fields, "location", params.Location)
	setOptional(fields, "login_challenge", params.LoginChallenge)

	result, err := surrealdb.Create[oauth.ApprovalRequest](ctx, s.DB, "approval_request", fields)
	if err != nil {
		return nil, fmt.Errorf("create approval request: %w", err)
	}
	return result, nil
}

func (s *SurrealStore) ListPendingApprovals(ctx context.Context, userID string) ([]*oauth.ApprovalRequest, error) {
	return s.queryApprovals(ctx,
		`SELECT * FROM approval_request
		 WHERE user = $user AND status = "pending" AND expires_at > time::now()
		 ORDER BY created_at DESC`,
		map[string]any{"user": models.NewRecordID("user", userID)},
	)
}

func (s *SurrealStore) ListApprovalHistory(ctx context.Context, userID string, limit int) ([]*oauth.ApprovalRequest, error) {
	return s.queryApprovals(ctx,
		`SELECT * FROM approval_request
		 WHERE user = $user
		 ORDER BY created_at DESC
		 LIMIT $limit`,
		map[string]any{"user": models.NewRecordID("user", userID), "limit": limit},
	)
}

func (s *SurrealStore) GetApprovalRequest(ctx context.Context, userID, id string) (*oauth.ApprovalRequest, error) {
	results, err := s.queryApprovals(ctx,
		`SELECT * FROM approval_request WHERE id = $id AND user = $user LIMIT 1`,
		map[string]any{
			"id":   models.NewRecordID("approval_request", id),
			"user": models.NewRecordID("user", userID),
		},
	)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, ErrNotFound
	}
	return results[0], nil
}

// DecideApprovalRequest atomically moves a pending request to approved/denied,
// scoped to the owning user. Returns ErrNotFound if it was already decided,
// expired, or belongs to another user — preventing double or cross-user decides.
func (s *SurrealStore) DecideApprovalRequest(ctx context.Context, userID, id, status string) (*oauth.ApprovalRequest, error) {
	results, err := s.queryApprovals(ctx,
		`UPDATE approval_request SET status = $status, decided_at = time::now()
		 WHERE id = $id AND user = $user AND status = "pending"
		 RETURN AFTER`,
		map[string]any{
			"id":     models.NewRecordID("approval_request", id),
			"user":   models.NewRecordID("user", userID),
			"status": status,
		},
	)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, ErrNotFound
	}
	return results[0], nil
}

func (s *SurrealStore) queryApprovals(ctx context.Context, query string, vars map[string]any) ([]*oauth.ApprovalRequest, error) {
	results, err := surrealdb.Query[[]oauth.ApprovalRequest](ctx, s.DB, query, vars)
	if err != nil {
		return nil, fmt.Errorf("query approvals: %w", err)
	}
	for _, qr := range *results {
		out := make([]*oauth.ApprovalRequest, len(qr.Result))
		for i := range qr.Result {
			out[i] = &qr.Result[i]
		}
		return out, nil
	}
	return nil, nil
}

// ── Push tokens ────────────────────────────────────────────────────────────────

func (s *SurrealStore) UpsertPushToken(ctx context.Context, userID string, deviceID *string, platform, token string) error {
	fields := map[string]any{
		"user":     models.NewRecordID("user", userID),
		"platform": platform,
		"token":    token,
	}
	if deviceID != nil {
		fields["device"] = models.NewRecordID("device", *deviceID)
	}
	_, err := surrealdb.Query[[]any](ctx, s.DB,
		`UPSERT push_token SET user = $user, device = $device, platform = $platform, token = $token
		 WHERE token = $token`,
		fields,
	)
	if err != nil {
		return fmt.Errorf("upsert push token: %w", err)
	}
	return nil
}

func (s *SurrealStore) ListPushTokensForUser(ctx context.Context, userID string) ([]*oauth.PushToken, error) {
	results, err := surrealdb.Query[[]oauth.PushToken](ctx, s.DB,
		`SELECT * FROM push_token WHERE user = $user`,
		map[string]any{"user": models.NewRecordID("user", userID)},
	)
	if err != nil {
		return nil, fmt.Errorf("list push tokens: %w", err)
	}
	for _, qr := range *results {
		out := make([]*oauth.PushToken, len(qr.Result))
		for i := range qr.Result {
			out[i] = &qr.Result[i]
		}
		return out, nil
	}
	return nil, nil
}

func setOptional(fields map[string]any, key string, value *string) {
	if value != nil {
		fields[key] = *value
	}
}
