// Package connectionlease caps the long-lived connections of one caller across
// every API instance sharing a Redis. Each open connection holds a lease in a
// sorted set scored by its expiry and renews it while open, so the leases of a
// crashed instance lapse on their own.
package connectionlease

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	leaseDuration = 90 * time.Second
	leaseRenewal  = leaseDuration / 3
	redisTimeout  = 10 * time.Second
)

// acquireScript counts the live leases in a sorted set scored by expiry and
// adds one when the caller is below the limit. KEYS[1] is the set; ARGV holds
// now and the new expiry in milliseconds, the limit, the lease id and the set's
// time to live.
var acquireScript = redis.NewScript(`
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[3]) then
	return 0
end
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[4])
redis.call('PEXPIRE', KEYS[1], ARGV[5])
return 1
`)

type Leases struct {
	client *redis.Client
}

func New(client *redis.Client) Leases {
	return Leases{client: client}
}

// Lease is one connection's place under its caller's cap.
type Lease struct {
	key string
	id  string
}

// Acquire takes a place under key when fewer than limit leases are live. It
// reports false when the caller is at the limit.
func (leases Leases) Acquire(ctx context.Context, key string, limit int) (Lease, bool, error) {
	acquired := Lease{key: key, id: newLeaseID()}
	now := time.Now()
	arguments := []any{now.UnixMilli(), now.Add(leaseDuration).UnixMilli(), limit, acquired.id, leaseDuration.Milliseconds()}
	admitted, err := acquireScript.Run(ctx, leases.client, []string{key}, arguments...).Int()
	if err != nil {
		return Lease{}, false, err
	}
	return acquired, admitted == 1, nil
}

// Hold renews the lease until done is closed.
func (leases Leases) Hold(held Lease, done <-chan struct{}) {
	ticker := time.NewTicker(leaseRenewal)
	defer ticker.Stop()
	for renewalDue(ticker.C, done) {
		leases.renew(held)
	}
}

func (leases Leases) Release(held Lease) {
	ctx, cancel := context.WithTimeout(context.Background(), redisTimeout)
	defer cancel()
	if err := leases.client.ZRem(ctx, held.key, held.id).Err(); err != nil {
		slog.Warn("connection lease release", "error", err)
	}
}

func (leases Leases) renew(held Lease) {
	ctx, cancel := context.WithTimeout(context.Background(), redisTimeout)
	defer cancel()
	expiry := float64(time.Now().Add(leaseDuration).UnixMilli())
	pipeline := leases.client.TxPipeline()
	pipeline.ZAddXX(ctx, held.key, redis.Z{Score: expiry, Member: held.id})
	pipeline.PExpire(ctx, held.key, leaseDuration)
	if _, err := pipeline.Exec(ctx); err != nil {
		slog.Warn("connection lease renewal", "error", err)
	}
}

func renewalDue(tick <-chan time.Time, done <-chan struct{}) bool {
	select {
	case <-tick:
		return true
	case <-done:
		return false
	}
}

func newLeaseID() string {
	random := make([]byte, 16)
	_, _ = rand.Read(random)
	return hex.EncodeToString(random)
}
