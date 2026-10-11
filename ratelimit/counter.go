package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Counter counts hits per key inside a window.
type Counter interface {
	// Hit adds one to the key and returns the count in the current window and
	// how long the window still lasts.
	Hit(ctx context.Context, key string, window time.Duration) (int64, time.Duration, error)
	// Peek reads the count and the time left without counting a hit; zero when
	// the key has no window running.
	Peek(ctx context.Context, key string) (int64, time.Duration, error)
}

// UsageRecorder keeps the daily request counts the usage page of an app reports.
type UsageRecorder interface {
	Record(ctx context.Context, clientID string, limited bool) error
	Daily(ctx context.Context, clientID string, days int) ([]DayCount, error)
}

// DayCount is the calls a client made on one UTC day, and how many were refused.
type DayCount struct {
	Date        string
	Requests    int64
	RateLimited int64
}

const usageRetention = 45 * 24 * time.Hour

// hitScript counts a hit and starts the window on the first one, atomically.
var hitScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if count == 1 then
	redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return {count, redis.call('PTTL', KEYS[1])}
`)

// RedisCounter counts in Redis.
type RedisCounter struct {
	client *redis.Client
	now    func() time.Time
}

func NewRedisCounter(client *redis.Client) *RedisCounter {
	return &RedisCounter{client: client, now: time.Now}
}

func (counter *RedisCounter) Hit(ctx context.Context, key string, window time.Duration) (int64, time.Duration, error) {
	result, err := hitScript.Run(ctx, counter.client, []string{key}, window.Milliseconds()).Int64Slice()
	if err != nil {
		return 0, 0, err
	}
	if len(result) != 2 {
		return 0, 0, fmt.Errorf("rate limit script returned %d values", len(result))
	}
	return result[0], time.Duration(result[1]) * time.Millisecond, nil
}

func (counter *RedisCounter) Peek(ctx context.Context, key string) (int64, time.Duration, error) {
	pipeline := counter.client.Pipeline()
	count := pipeline.Get(ctx, key)
	remaining := pipeline.PTTL(ctx, key)
	if _, err := pipeline.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return 0, 0, err
	}
	if errors.Is(count.Err(), redis.Nil) {
		return 0, 0, nil
	}
	return parseCount(count.Val()), remaining.Val(), nil
}

func usageKey(clientID string, day time.Time) string {
	return "usage:" + clientID + ":" + day.UTC().Format("20060102")
}

// Record counts one call of the client today, and one refused call when limited.
func (counter *RedisCounter) Record(ctx context.Context, clientID string, limited bool) error {
	key := usageKey(clientID, counter.now())
	pipeline := counter.client.Pipeline()
	pipeline.HIncrBy(ctx, key, "requests", 1)
	if limited {
		pipeline.HIncrBy(ctx, key, "limited", 1)
	}
	pipeline.Expire(ctx, key, usageRetention)
	_, err := pipeline.Exec(ctx)
	return err
}

// Daily returns the counts of the last days days, oldest first, today included.
func (counter *RedisCounter) Daily(ctx context.Context, clientID string, days int) ([]DayCount, error) {
	counts := make([]DayCount, 0, days)
	for offset := days - 1; offset >= 0; offset-- {
		day := counter.now().UTC().AddDate(0, 0, -offset)
		fields, err := counter.client.HGetAll(ctx, usageKey(clientID, day)).Result()
		if err != nil {
			return nil, err
		}
		counts = append(counts, DayCount{
			Date: day.Format("2006-01-02"), Requests: parseCount(fields["requests"]), RateLimited: parseCount(fields["limited"]),
		})
	}
	return counts, nil
}

func parseCount(text string) int64 {
	count, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0
	}
	return count
}
