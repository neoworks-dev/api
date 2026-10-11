package contactcodes

import (
	"context"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/ratelimit"
)

const (
	lookupWindow = time.Minute
	failedWindow = 10 * time.Minute
)

// lookupLimiter limits contact code lookups per user, per address and for the
// failed ones of a user, which is what stops guessing. The counters are shared
// through Redis when the handler has one.
type lookupLimiter struct {
	counter ratelimit.Counter
}

// wait is how long the caller must wait before looking up another code; zero
// when it may. It counts the lookup against the user and address limits. A
// counter that fails lets the lookup through.
func (limiter lookupLimiter) wait(ctx context.Context, userID string, address string) time.Duration {
	wait := limiter.hit(ctx, "contacts:user:"+userID, lookupsPerUserPerMinute, lookupWindow)
	wait = max(wait, limiter.hit(ctx, "contacts:address:"+address, lookupsPerAddressPerMinute, lookupWindow))
	return max(wait, limiter.failedWait(ctx, userID))
}

func (limiter lookupLimiter) hit(ctx context.Context, key string, limit int, window time.Duration) time.Duration {
	count, remaining, err := limiter.counter.Hit(ctx, key, window)
	if err != nil {
		slog.Warn("contact code limiter unavailable", "error", err)
		return 0
	}
	if count <= int64(limit) {
		return 0
	}
	return remaining
}

func (limiter lookupLimiter) failedWait(ctx context.Context, userID string) time.Duration {
	count, remaining, err := limiter.counter.Peek(ctx, "contacts:failed:"+userID)
	if err != nil {
		slog.Warn("contact code limiter unavailable", "error", err)
		return 0
	}
	if count < failedLookupsPerTenMinutes {
		return 0
	}
	return remaining
}

// recordFailure counts a lookup that found nothing.
func (limiter lookupLimiter) recordFailure(ctx context.Context, userID string) {
	if _, _, err := limiter.counter.Hit(ctx, "contacts:failed:"+userID, failedWindow); err != nil {
		slog.Warn("contact code limiter unavailable", "error", err)
	}
}

func writeLimited(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
	respond.Error(w, http.StatusTooManyRequests, "rate_limited", "too many contact code lookups; try again later")
}
