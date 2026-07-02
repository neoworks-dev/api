package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Email verification and password-reset state.
//
// Codes are short-lived (10 min) and scoped by purpose ("signup" | "reset") so a
// signup code can never satisfy a reset and vice-versa. Once a signup code is
// verified we keep a separate "verified" flag (15 min) that the final signup
// submission must find — this is what guarantees an account is only created for
// an email the user provably controls. Reset uses a one-time token instead, so
// the second step (re-wrapping the AMK) can prove the first step (code entry)
// happened without re-sending the code.
const (
	verificationCodeTTL = 10 * time.Minute
	emailVerifiedTTL    = 15 * time.Minute
	resetTokenTTL       = 10 * time.Minute
)

func (r *RedisStore) SaveVerificationCode(ctx context.Context, purpose, email, code string) error {
	return r.client.SetEx(ctx, verificationCodeKey(purpose, email), code, verificationCodeTTL).Err()
}

func (r *RedisStore) GetVerificationCode(ctx context.Context, purpose, email string) (string, error) {
	code, err := r.client.Get(ctx, verificationCodeKey(purpose, email)).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get verification code: %w", err)
	}
	return code, nil
}

func (r *RedisStore) DeleteVerificationCode(ctx context.Context, purpose, email string) error {
	return r.client.Del(ctx, verificationCodeKey(purpose, email)).Err()
}

// MarkEmailVerified records that the given email passed the signup code check.
// The final signup POST consumes this flag via IsEmailVerified.
func (r *RedisStore) MarkEmailVerified(ctx context.Context, email string) error {
	return r.client.SetEx(ctx, emailVerifiedKey(email), "1", emailVerifiedTTL).Err()
}

func (r *RedisStore) IsEmailVerified(ctx context.Context, email string) (bool, error) {
	_, err := r.client.Get(ctx, emailVerifiedKey(email)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("get email verified: %w", err)
	}
	return true, nil
}

func (r *RedisStore) ClearEmailVerified(ctx context.Context, email string) error {
	return r.client.Del(ctx, emailVerifiedKey(email)).Err()
}

// SaveResetToken issues a one-time token bound to an email after the reset code
// was verified. ConsumeResetToken returns the email and deletes the token so it
// cannot be replayed.
func (r *RedisStore) SaveResetToken(ctx context.Context, token, email string) error {
	return r.client.SetEx(ctx, resetTokenKey(token), email, resetTokenTTL).Err()
}

func (r *RedisStore) ConsumeResetToken(ctx context.Context, token string) (string, error) {
	email, err := r.client.GetDel(ctx, resetTokenKey(token)).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("consume reset token: %w", err)
	}
	return email, nil
}

func verificationCodeKey(purpose, email string) string {
	return fmt.Sprintf("verify:%s:%s", purpose, email)
}
func emailVerifiedKey(email string) string { return fmt.Sprintf("verified:signup:%s", email) }
func resetTokenKey(token string) string    { return fmt.Sprintf("reset_token:%s", token) }
