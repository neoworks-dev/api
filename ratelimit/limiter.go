package ratelimit

import (
	"context"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/storage/database"
)

const standingTTL = 15 * time.Second

// StandingSource reads how a client stands with Neoworks.
type StandingSource interface {
	GetClientStanding(ctx context.Context, clientID string) (*database.ClientStanding, error)
}

type cachedStanding struct {
	standing database.ClientStanding
	expires  time.Time
}

// Limiter enforces the limits. When Redis fails it lets calls through: an
// outage of the counters must not take the API down.
type Limiter struct {
	counter   Counter
	usage     UsageRecorder
	standings StandingSource
	limits    map[Bucket]Limit
	now       func() time.Time

	mutex sync.Mutex
	cache map[string]cachedStanding
}

func New(counter Counter, usage UsageRecorder, standings StandingSource) *Limiter {
	return &Limiter{
		counter: counter, usage: usage, standings: standings, limits: DefaultLimits,
		now: time.Now, cache: map[string]cachedStanding{},
	}
}

// bucketFor decides which limit a call to an authenticated route counts
// against. Blob presigns are limited by their handler, which knows whether the
// call uploads or downloads.
func bucketFor(r *http.Request) (Bucket, bool) {
	path := r.URL.Path
	switch {
	case path == "/api/v1/blobs/presign":
		return "", false
	case path == "/api/v1/nodes/push":
		return BucketPush, true
	case strings.HasPrefix(path, "/api/v1/nodes/") && r.Method == http.MethodGet:
		return BucketSync, true
	case path == "/api/v1/keys/identity" || strings.HasSuffix(path, "/identity-keys"):
		return BucketIdentity, true
	}
	return BucketGeneral, true
}

// Authenticated limits the calls of a resolved principal and refuses the calls
// of suspended apps. It must run after the principal middleware.
func (limiter *Limiter) Authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bucket, limited := bucketFor(r)
		if limited && !limiter.Allow(w, r, bucket) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Allow counts a call of the request's principal against the bucket. When the
// call is refused it has written the response and Allow returns false.
func (limiter *Limiter) Allow(w http.ResponseWriter, r *http.Request, bucket Bucket) bool {
	principal, found := middleware.PrincipalFromContext(r.Context())
	if !found {
		return true
	}
	standing := limiter.standingOf(r.Context(), principal.ClientID)
	if standing.Suspended() {
		respond.Error(w, http.StatusForbidden, "app_suspended", "Neoworks suspended this app")
		return false
	}
	multiplier := MultiplierFor(&standing)
	limit := limiter.limits[bucket]
	retryAfter := limiter.hitBoth(r.Context(), bucket, principal.ClientID, principal.UserID, scaled(limit.PerClient, multiplier), scaled(limit.PerUserClient, multiplier))
	limiter.record(r.Context(), principal.ClientID, retryAfter > 0)
	if retryAfter > 0 {
		writeLimited(w, retryAfter)
		return false
	}
	return true
}

// hitBoth counts against the client's limit and the user's limit within it and
// returns how long to wait, or zero when the call may go on.
func (limiter *Limiter) hitBoth(ctx context.Context, bucket Bucket, clientID string, userID string, clientLimit int, userLimit int) time.Duration {
	clientKey := "rl:" + string(bucket) + ":client:" + clientID
	if wait := limiter.hit(ctx, clientKey, clientLimit); wait > 0 {
		return wait
	}
	return limiter.hit(ctx, "rl:"+string(bucket)+":user:"+clientID+":"+userID, userLimit)
}

// hit counts one call and returns how long until the key's window ends when the
// call is over the limit; zero otherwise.
func (limiter *Limiter) hit(ctx context.Context, key string, limit int) time.Duration {
	count, remaining, err := limiter.counter.Hit(ctx, key, Window)
	if err != nil {
		slog.Warn("rate limit counter unavailable", "error", err)
		return 0
	}
	if count <= int64(limit) {
		return 0
	}
	return remaining
}

func (limiter *Limiter) record(ctx context.Context, clientID string, limited bool) {
	if err := limiter.usage.Record(ctx, clientID, limited); err != nil {
		slog.Warn("record client usage", "error", err)
	}
}

// standingOf returns the standing of the client, from a short-lived cache. A
// client it cannot read is treated as an ordinary one.
func (limiter *Limiter) standingOf(ctx context.Context, clientID string) database.ClientStanding {
	limiter.mutex.Lock()
	cached, found := limiter.cache[clientID]
	limiter.mutex.Unlock()
	if found && limiter.now().Before(cached.expires) {
		return cached.standing
	}
	standing, err := limiter.standings.GetClientStanding(ctx, clientID)
	if err != nil {
		return database.ClientStanding{ReviewStatus: database.ReviewStatusNone}
	}
	limiter.mutex.Lock()
	limiter.cache[clientID] = cachedStanding{standing: *standing, expires: limiter.now().Add(standingTTL)}
	limiter.mutex.Unlock()
	return *standing
}

// ByIP limits callers without a token by their IP address.
func (limiter *Limiter) ByIP(bucket Bucket) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := "rl:" + string(bucket) + ":ip:" + ClientIP(r)
			if wait := limiter.hit(r.Context(), key, limiter.limits[bucket].PerIP); wait > 0 {
				writeLimited(w, wait)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// TakeUser counts one call of a user of a client against the bucket and returns
// how long to wait when the call is over the limit; zero otherwise.
func (limiter *Limiter) TakeUser(ctx context.Context, bucket Bucket, clientID string, userID string) time.Duration {
	key := "rl:" + string(bucket) + ":user:" + clientID + ":" + userID
	return limiter.hit(ctx, key, limiter.limits[bucket].PerUserClient)
}

// TakeIP counts one call of an IP address against the bucket and returns how
// long to wait when the call is over the limit; zero otherwise.
func (limiter *Limiter) TakeIP(ctx context.Context, bucket Bucket, ip string) time.Duration {
	return limiter.hit(ctx, "rl:"+string(bucket)+":ip:"+ip, limiter.limits[bucket].PerIP)
}

// ClientIP is the address the request came from; the router's RealIP
// middleware has already replaced it with the forwarded one.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeLimited(w http.ResponseWriter, wait time.Duration) {
	seconds := int(math.Ceil(wait.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	respond.JSON(w, http.StatusTooManyRequests, map[string]any{
		"error": "rate_limited", "message": "too many requests; retry after the delay", "retryAfter": seconds,
	})
}
