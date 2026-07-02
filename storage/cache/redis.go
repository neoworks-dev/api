package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/neoworks/auth/oauth"
	"github.com/redis/go-redis/v9"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrTokenReplayed = errors.New("refresh token already used — possible replay attack")
)

type RedisStore struct {
	client *redis.Client
}

func NewRedisStore(addr string) *RedisStore {
	return &RedisStore{
		client: redis.NewClient(&redis.Options{Addr: addr}),
	}
}

// ── Authorization codes ──────────────────────────────────────────────────────

func (store *RedisStore) SaveAuthCode(ctx context.Context, code oauth.AuthCode) error {
	data, err := json.Marshal(code)
	if err != nil {
		return err
	}
	ttl := time.Until(code.ExpiresAt)
	return store.client.Set(ctx, authCodeKey(code.Code), data, ttl).Err()
}

func (store *RedisStore) ConsumeAuthCode(ctx context.Context, code string) (*oauth.AuthCode, error) {
	key := authCodeKey(code)

	// GET + DEL in a single round-trip
	pipe := store.client.Pipeline()
	get := pipe.Get(ctx, key)
	pipe.Del(ctx, key)
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, err
	}

	data, err := get.Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	var ac oauth.AuthCode
	if err := json.Unmarshal(data, &ac); err != nil {
		return nil, err
	}
	return &ac, nil
}

// ── Refresh token rotation lock ───────────────────────────────────────────────
// SetNX returns false if the key already exists — another request is currently
// rotating the same token. That is concurrency, NOT necessarily a replay: the
// caller should wait for the in-flight rotation result rather than revoke the
// grant. Genuine replay is detected via the token's Used flag once the grace
// window (see SaveRotationResult) has expired.

func (store *RedisStore) AcquireRotationLock(ctx context.Context, jti string) error {
	ok, err := store.client.SetNX(ctx, rotationLockKey(jti), "1", 30*time.Second).Result()
	if err != nil {
		return err
	}
	if !ok {
		return ErrTokenReplayed
	}
	return nil
}

// ── Refresh token rotation grace window ───────────────────────────────────────
// After a token rotates, the issued response is cached under the OLD token id.
// Concurrent requests (parallel SSR loads, multiple tabs, retries) that present
// the same old token within the window receive the identical new tokens instead
// of an error — making refresh idempotent under concurrency.

func (store *RedisStore) SaveRotationResult(ctx context.Context, jti string, resp oauth.TokenResponse, ttl time.Duration) error {
	return store.saveJSON(ctx, rotationResultKey(jti), resp, ttl)
}

func (store *RedisStore) GetRotationResult(ctx context.Context, jti string) (*oauth.TokenResponse, error) {
	var resp oauth.TokenResponse
	if err := store.getJSON(ctx, rotationResultKey(jti), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ── Access token revocation ───────────────────────────────────────────────────

func (store *RedisStore) RevokeAccessToken(ctx context.Context, jti string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return nil // already expired, nothing to do
	}
	return store.client.Set(ctx, revokedKey(jti), "1", ttl).Err()
}

func (store *RedisStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	n, err := store.client.Exists(ctx, revokedKey(jti)).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (store *RedisStore) RevokeAccessTokens(ctx context.Context, jtis []string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 || len(jtis) == 0 {
		return nil
	}
	pipe := store.client.Pipeline()
	for _, jti := range jtis {
		pipe.SetEx(ctx, revokedKey(jti), "1", ttl)
	}
	_, err := pipe.Exec(ctx)
	return err
}

// ── Login / consent challenges ────────────────────────────────────────────────

func (store *RedisStore) SaveLoginChallenge(ctx context.Context, c oauth.LoginChallenge) error {
	return store.saveJSON(ctx, loginChallengeKey(c.ID), c, time.Until(c.ExpiresAt))
}

func (store *RedisStore) GetLoginChallenge(ctx context.Context, id string) (*oauth.LoginChallenge, error) {
	var c oauth.LoginChallenge
	if err := store.getJSON(ctx, loginChallengeKey(id), &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (store *RedisStore) DeleteLoginChallenge(ctx context.Context, id string) error {
	return store.client.Del(ctx, loginChallengeKey(id)).Err()
}

func (store *RedisStore) SaveConsentChallenge(ctx context.Context, challenge oauth.ConsentChallenge) error {
	return store.saveJSON(ctx, consentChallengeKey(challenge.ID), challenge, time.Until(challenge.ExpiresAt))
}

func (store *RedisStore) GetConsentChallenge(ctx context.Context, id string) (*oauth.ConsentChallenge, error) {
	var c oauth.ConsentChallenge
	if err := store.getJSON(ctx, consentChallengeKey(id), &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (store *RedisStore) DeleteConsentChallenge(ctx context.Context, id string) error {
	return store.client.Del(ctx, consentChallengeKey(id)).Err()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (store *RedisStore) saveJSON(ctx context.Context, key string, v any, ttl time.Duration) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return store.client.SetEx(ctx, key, data, ttl).Err()
}

func (store *RedisStore) getJSON(ctx context.Context, key string, dest any) error {
	data, err := store.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dest)
}

// ── Generic byte cache ────────────────────────────────────────────────────────
// Used by the assets service to cache hot object bytes and avoid S3 round-trips.

func (store *RedisStore) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	return store.client.Set(ctx, key, val, ttl).Err()
}

func (store *RedisStore) Get(ctx context.Context, key string) ([]byte, error) {
	data, err := store.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

func authCodeKey(code string) string       { return fmt.Sprintf("code:%s", code) }
func rotationLockKey(jti string) string    { return fmt.Sprintf("rt_lock:%s", jti) }
func rotationResultKey(jti string) string  { return fmt.Sprintf("rt_result:%s", jti) }
func revokedKey(jti string) string         { return fmt.Sprintf("revoked:%s", jti) }
func loginChallengeKey(id string) string   { return fmt.Sprintf("login_challenge:%s", id) }
func consentChallengeKey(id string) string { return fmt.Sprintf("consent_challenge:%s", id) }

