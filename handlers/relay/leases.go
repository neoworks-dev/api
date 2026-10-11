package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// leaseDuration is how long a connection counts against its caller's cap
// without being renewed, so the connections of a crashed instance free up on
// their own.
const (
	leaseDuration = 90 * time.Second
	leaseRenewal  = leaseDuration / 3
)

// acquireScript counts the live leases in a sorted set scored by expiry and
// adds one when the caller is below the limit. KEYS[1] is the set; ARGV holds
// now and the new expiry in milliseconds, the limit and the lease id.
var acquireScript = redis.NewScript(`
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[3]) then
	return 0
end
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[4])
redis.call('PEXPIRE', KEYS[1], ARGV[5])
return 1
`)

// connectionLeases caps the open connections of one caller across every API
// instance sharing the Redis.
type connectionLeases struct {
	client *redis.Client
}

type lease struct {
	key string
	id  string
}

func leaseKey(who identity) string {
	if who.signedIn() {
		return "relay:connections:user:" + channelName(who.clientID, who.userID)
	}
	return "relay:connections:ip:" + who.ip
}

func (leases connectionLeases) acquire(ctx context.Context, who identity, limit int) (lease, bool, error) {
	acquired := lease{key: leaseKey(who), id: newLeaseID()}
	now := time.Now()
	arguments := []any{now.UnixMilli(), now.Add(leaseDuration).UnixMilli(), limit, acquired.id, leaseDuration.Milliseconds()}
	admitted, err := acquireScript.Run(ctx, leases.client, []string{acquired.key}, arguments...).Int()
	if err != nil {
		return lease{}, false, err
	}
	return acquired, admitted == 1, nil
}

// renew pushes the expiry of the lease out while the connection is open.
func (leases connectionLeases) renew(held lease) {
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	expiry := float64(time.Now().Add(leaseDuration).UnixMilli())
	pipeline := leases.client.TxPipeline()
	pipeline.ZAddXX(ctx, held.key, redis.Z{Score: expiry, Member: held.id})
	pipeline.PExpire(ctx, held.key, leaseDuration)
	if _, err := pipeline.Exec(ctx); err != nil {
		slog.Warn("relay lease renewal", "error", err)
	}
}

func (leases connectionLeases) release(held lease) {
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	if err := leases.client.ZRem(ctx, held.key, held.id).Err(); err != nil {
		slog.Warn("relay lease release", "error", err)
	}
}

// keepRenewed renews the lease until done is closed.
func (leases connectionLeases) keepRenewed(held lease, done <-chan struct{}) {
	ticker := time.NewTicker(leaseRenewal)
	defer ticker.Stop()
	for renewalDue(ticker.C, done) {
		leases.renew(held)
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
