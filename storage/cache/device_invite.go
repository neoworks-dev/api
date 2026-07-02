package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type DeviceInvite struct {
	DevicePublicKey string `json:"device_public_key"`
}

type DeviceInviteResult struct {
	WrappedAMK string `json:"wrapped_amk"`
}

func (r *RedisStore) CreateDeviceInvite(ctx context.Context, token string, invite DeviceInvite) error {
	data, err := json.Marshal(invite)
	if err != nil {
		return err
	}
	return r.client.SetEx(ctx, deviceInviteKey(token), data, 10*time.Minute).Err()
}

func (r *RedisStore) GetDeviceInvite(ctx context.Context, token string) (*DeviceInvite, error) {
	data, err := r.client.Get(ctx, deviceInviteKey(token)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get device invite: %w", err)
	}
	var invite DeviceInvite
	if err := json.Unmarshal(data, &invite); err != nil {
		return nil, err
	}
	return &invite, nil
}

func (r *RedisStore) SetDeviceInviteResult(ctx context.Context, token string, result DeviceInviteResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return r.client.SetEx(ctx, deviceInviteResultKey(token), data, time.Hour).Err()
}

func (r *RedisStore) GetDeviceInviteResult(ctx context.Context, token string) (*DeviceInviteResult, error) {
	data, err := r.client.Get(ctx, deviceInviteResultKey(token)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get device invite result: %w", err)
	}
	var result DeviceInviteResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func deviceInviteKey(token string) string       { return fmt.Sprintf("device_invite:%s", token) }
func deviceInviteResultKey(token string) string { return fmt.Sprintf("device_invite_result:%s", token) }
