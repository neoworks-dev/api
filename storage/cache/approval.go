package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Bridges the cross-process sign-in approval: the oauth login page writes a
// challenge→request link, the api server (where the phone approves) writes the
// result, and the oauth login page polls the result to finish the login.

// ApprovalLink maps a login_challenge to the approval_request created for it.
type ApprovalLink struct {
	ApprovalRequestID string `json:"approval_request_id"`
}

// ApprovalResult is the decision the polling login page waits for.
type ApprovalResult struct {
	Status string `json:"status"` // approved | denied
	UserID string `json:"user_id"`
}

func (store *RedisStore) LinkChallengeApproval(ctx context.Context, challengeID string, link ApprovalLink) error {
	return store.saveJSON(ctx, approvalChallengeKey(challengeID), link, 10*time.Minute)
}

func (store *RedisStore) GetChallengeApproval(ctx context.Context, challengeID string) (*ApprovalLink, error) {
	var link ApprovalLink
	if err := store.getJSON(ctx, approvalChallengeKey(challengeID), &link); err != nil {
		return nil, err
	}
	return &link, nil
}

func (store *RedisStore) SetApprovalResult(ctx context.Context, challengeID string, res ApprovalResult) error {
	return store.saveJSON(ctx, approvalResultKey(challengeID), res, 10*time.Minute)
}

func (store *RedisStore) GetApprovalResult(ctx context.Context, challengeID string) (*ApprovalResult, error) {
	var res ApprovalResult
	if err := store.getJSON(ctx, approvalResultKey(challengeID), &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// IsApprovalLinked reports whether a request was created for this challenge,
// so the login page can distinguish "pending" from "never requested".
func (store *RedisStore) IsApprovalLinked(ctx context.Context, challengeID string) (bool, error) {
	n, err := store.client.Exists(ctx, approvalChallengeKey(challengeID)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func approvalChallengeKey(id string) string { return fmt.Sprintf("approval_challenge:%s", id) }
func approvalResultKey(id string) string    { return fmt.Sprintf("approval_result:%s", id) }
