package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/redis/go-redis/v9"
)

// An SSO session belongs to a single device (the sso_session cookie) but may
// hold several signed-in accounts. The accounts are stored as a JSON list where
// index 0 is the active account — the one returned to single-account callers
// (FedCM, the session bridge, the keys middleware).

// decodeAccounts parses the stored value. Sessions written before multi-account
// support held a bare user id; treat such a value as a single-account list so
// existing sessions keep working.
func decodeAccounts(raw string) []string {
	var accounts []string
	if err := json.Unmarshal([]byte(raw), &accounts); err != nil {
		return []string{raw}
	}
	return accounts
}

func (r *RedisStore) GetSSOAccounts(ctx context.Context, token string) ([]string, error) {
	val, err := r.client.Get(ctx, "sso:"+token).Result()
	if err == redis.Nil {
		return nil, errors.New("session not found")
	}
	if err != nil {
		return nil, fmt.Errorf("get sso session: %w", err)
	}
	return decodeAccounts(val), nil
}

// GetSSOSession returns the active account for the session. Callers that only
// understand a single user (FedCM, session bridge, keys middleware) use this.
func (r *RedisStore) GetSSOSession(ctx context.Context, token string) (string, error) {
	accounts, err := r.GetSSOAccounts(ctx, token)
	if err != nil {
		return "", err
	}
	if len(accounts) == 0 {
		return "", errors.New("session not found")
	}
	return accounts[0], nil
}

func (r *RedisStore) saveAccounts(ctx context.Context, token string, accounts []string, ttl time.Duration) error {
	encoded, err := json.Marshal(accounts)
	if err != nil {
		return fmt.Errorf("encode sso accounts: %w", err)
	}
	return r.client.Set(ctx, "sso:"+token, encoded, ttl).Err()
}

// SaveSSOSession creates a fresh session holding a single account.
func (r *RedisStore) SaveSSOSession(ctx context.Context, token string, userID string, ttl time.Duration) error {
	return r.saveAccounts(ctx, token, []string{userID}, ttl)
}

// AddSSOAccount adds userID to the session and marks it active (moves it to the
// front). The session is created if it does not exist yet. The TTL is refreshed.
func (r *RedisStore) AddSSOAccount(ctx context.Context, token string, userID string, ttl time.Duration) error {
	accounts, err := r.GetSSOAccounts(ctx, token)
	if err != nil {
		accounts = nil
	}
	return r.saveAccounts(ctx, token, moveToFront(accounts, userID), ttl)
}

// SetActiveSSOAccount marks an account already in the session as active. It does
// nothing when the account is not part of the session, so a caller cannot make
// the session active for an account the device never signed into.
func (r *RedisStore) SetActiveSSOAccount(ctx context.Context, token string, userID string, ttl time.Duration) error {
	accounts, err := r.GetSSOAccounts(ctx, token)
	if err != nil {
		return err
	}
	if !slices.Contains(accounts, userID) {
		return errors.New("account not in session")
	}
	return r.saveAccounts(ctx, token, moveToFront(accounts, userID), ttl)
}

func (r *RedisStore) RefreshSSOSession(ctx context.Context, token string, ttl time.Duration) error {
	return r.client.Expire(ctx, "sso:"+token, ttl).Err()
}

func (r *RedisStore) DeleteSSOSession(ctx context.Context, token string) error {
	return r.client.Del(ctx, "sso:"+token).Err()
}

// moveToFront returns accounts with userID at index 0, removing any earlier
// occurrence so the list never holds duplicates.
func moveToFront(accounts []string, userID string) []string {
	result := []string{userID}
	for _, account := range accounts {
		if account != userID {
			result = append(result, account)
		}
	}
	return result
}
