package database

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrTenantBusy is returned when a tenant has too many concurrent queries in
// flight and the admission queue timed out. Callers map it to HTTP 429.
var ErrTenantBusy = errors.New("database busy")

// Throttler admits client-database queries per tenant so one noisy tenant on the
// shared instance cannot starve the others. Acquire blocks/queues up to an
// internal bound and returns a release func to call when the query completes, or
// ErrTenantBusy when admission is refused.
type Throttler interface {
	Acquire(ctx context.Context, namespace, plan string) (release func(), err error)
}

// acquireQuery gates a shared-instance query through the throttler. It is a no-op
// when no throttler is configured or the tenant is on a dedicated instance (a
// dedicated instance has no neighbours to protect).
func (s *SurrealStore) acquireQuery(ctx context.Context, route tenantRoute, namespace string) (func(), error) {
	if s.throttle == nil || !route.shared {
		return func() {}, nil
	}
	return s.throttle.Acquire(ctx, namespace, route.plan)
}

// ── Redis-coordinated throttler ──────────────────────────────────────────────

// ThrottleConfig bounds concurrent queries. Caps are per-tenant (free vs pro) plus
// a global ceiling on the shared instance; MaxWait is how long a query queues for a
// slot before giving up with ErrTenantBusy.
//
// Behaviour ranking: each tenant accrues a decayed "cost" score (recent query time,
// exponentially decayed with CostHalfLife). A tenant whose score exceeds
// CostThreshold is temporarily dropped to PenaltyCap — so a heavy tenant is
// throttled without touching its neighbours.
type ThrottleConfig struct {
	FreeCap       int           // base max concurrent queries for a free tenant
	ProCap        int           // base max concurrent queries for a pro tenant (still on shared)
	PenaltyCap    int           // reduced cap while a tenant is over the cost threshold
	GlobalCap     int           // max concurrent queries across all shared tenants
	CostThreshold float64       // decayed query-time (ms) above which a tenant is penalized
	CostHalfLife  time.Duration // half-life of the cost score
	LeaseTTL      time.Duration // safety expiry so a crashed pod's leases self-heal
	MaxWait       time.Duration // how long to queue for a slot before ErrTenantBusy
	Backoff       time.Duration // poll interval while queueing
}

// ThrottleConfigFromEnv reads the throttle knobs, falling back to defaults sized
// for the shared instance.
func ThrottleConfigFromEnv() ThrottleConfig {
	return ThrottleConfig{
		FreeCap:       envInt("DB_THROTTLE_FREE_CAP", 4),
		ProCap:        envInt("DB_THROTTLE_PRO_CAP", 8),
		PenaltyCap:    envInt("DB_THROTTLE_PENALTY_CAP", 1),
		GlobalCap:     envInt("DB_THROTTLE_GLOBAL_CAP", 64),
		CostThreshold: envFloat("DB_THROTTLE_COST_THRESHOLD", 5000),
		CostHalfLife:  envDuration("DB_THROTTLE_COST_HALFLIFE", 30*time.Second),
		LeaseTTL:      envDuration("DB_THROTTLE_LEASE_TTL", 30*time.Second),
		MaxWait:       envDuration("DB_THROTTLE_MAX_WAIT", 2*time.Second),
		Backoff:       envDuration("DB_THROTTLE_BACKOFF", 25*time.Millisecond),
	}
}

// admitScript atomically reaps expired leases, applies the behaviour-ranked cap,
// checks the tenant and global caps, and adds a lease when there's room. Returns 1
// admitted, 0 tenant full, -1 global full.
//
// KEYS: [tenant lease set, global lease set, tenant cost hash].
// ARGV: [leaseTTLms, baseCap, penaltyCap, globalCap, leaseID, costThreshold, tauMs].
// Time comes from Redis (TIME) so all pods share one clock.
var admitScript = redis.NewScript(`
local now = redis.call('TIME')
local nowMs = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
local expireAt = nowMs + tonumber(ARGV[1])
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, nowMs)
redis.call('ZREMRANGEBYSCORE', KEYS[2], 0, nowMs)
local score = tonumber(redis.call('HGET', KEYS[3], 's') or '0')
local ts = tonumber(redis.call('HGET', KEYS[3], 't') or nowMs)
local decay = math.exp(-(nowMs - ts) / tonumber(ARGV[7]))
if decay > 1 then decay = 1 end
score = score * decay
local cap = tonumber(ARGV[2])
if score > tonumber(ARGV[6]) then cap = tonumber(ARGV[3]) end
if redis.call('ZCARD', KEYS[1]) >= cap then return 0 end
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[4]) then return -1 end
redis.call('ZADD', KEYS[1], expireAt, ARGV[5])
redis.call('ZADD', KEYS[2], expireAt, ARGV[5])
local ttl = math.ceil(tonumber(ARGV[1]) / 1000) + 5
redis.call('EXPIRE', KEYS[1], ttl)
redis.call('EXPIRE', KEYS[2], ttl)
return 1
`)

// releaseScript removes a lease from both sets and folds the query's cost into the
// tenant's decayed score.
//
// KEYS: [tenant lease set, global lease set, tenant cost hash].
// ARGV: [leaseID, costMs, tauMs, costTTLsec].
var releaseScript = redis.NewScript(`
redis.call('ZREM', KEYS[1], ARGV[1])
redis.call('ZREM', KEYS[2], ARGV[1])
local now = redis.call('TIME')
local nowMs = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
local score = tonumber(redis.call('HGET', KEYS[3], 's') or '0')
local ts = tonumber(redis.call('HGET', KEYS[3], 't') or nowMs)
local decay = math.exp(-(nowMs - ts) / tonumber(ARGV[3]))
if decay > 1 then decay = 1 end
score = score * decay + tonumber(ARGV[2])
redis.call('HSET', KEYS[3], 's', score, 't', nowMs)
redis.call('EXPIRE', KEYS[3], tonumber(ARGV[4]))
return 1
`)

// RedisThrottler admits queries using Redis sorted-set leases so limits hold
// cluster-wide regardless of how many API replicas run.
type RedisThrottler struct {
	client *redis.Client
	cfg    ThrottleConfig
}

func NewRedisThrottler(client *redis.Client, cfg ThrottleConfig) *RedisThrottler {
	return &RedisThrottler{client: client, cfg: cfg}
}

const globalLeaseKey = "dbthrottle:leases:global"

func tenantLeaseKey(namespace string) string { return "dbthrottle:leases:" + namespace }
func tenantCostKey(namespace string) string  { return "dbthrottle:cost:" + namespace }

// Acquire admits one query for the tenant, queueing up to MaxWait for a slot. The
// returned release frees the slot and records the query's cost; it must be called
// exactly once.
func (t *RedisThrottler) Acquire(ctx context.Context, namespace, plan string) (func(), error) {
	baseCap := t.cfg.FreeCap
	if plan == "pro" {
		baseCap = t.cfg.ProCap
	}

	leaseID, err := newLeaseID()
	if err != nil {
		return nil, err
	}

	tenantKey := tenantLeaseKey(namespace)
	costKey := tenantCostKey(namespace)
	keys := []string{tenantKey, globalLeaseKey, costKey}
	tauMs := t.tauMs()
	argv := []any{
		t.cfg.LeaseTTL.Milliseconds(), baseCap, t.cfg.PenaltyCap, t.cfg.GlobalCap,
		leaseID, t.cfg.CostThreshold, tauMs,
	}
	deadline := time.Now().Add(t.cfg.MaxWait)

	for {
		res, err := admitScript.Run(ctx, t.client, keys, argv...).Int()
		if err != nil {
			return nil, err
		}
		if res == 1 {
			start := time.Now()
			return t.releaser(tenantKey, costKey, leaseID, start, tauMs), nil
		}
		if time.Now().After(deadline) {
			return nil, ErrTenantBusy
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(t.cfg.Backoff):
		}
	}
}

// releaser returns a func that frees the lease and folds the query's elapsed time
// into the tenant's cost score. It uses a fresh short-lived context so the slot is
// released even if the request context was cancelled.
func (t *RedisThrottler) releaser(tenantKey, costKey, leaseID string, start time.Time, tauMs float64) func() {
	return func() {
		costMs := float64(time.Since(start).Milliseconds())
		costTTLsec := int64(t.cfg.CostHalfLife.Seconds())*8 + 5
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = releaseScript.Run(ctx, t.client,
			[]string{tenantKey, globalLeaseKey, costKey},
			leaseID, costMs, tauMs, costTTLsec,
		).Err()
	}
}

// tauMs is the exponential decay time-constant in ms derived from the configured
// half-life (tau = halfLife / ln2).
func (t *RedisThrottler) tauMs() float64 {
	ms := float64(t.cfg.CostHalfLife.Milliseconds())
	if ms <= 0 {
		return 1
	}
	return ms / math.Ln2
}

func newLeaseID() (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return fallback
}

func envFloat(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			return f
		}
	}
	return fallback
}
