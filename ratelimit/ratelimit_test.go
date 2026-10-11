package ratelimit_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/ratelimit"
	"github.com/neoworks/auth/storage/database"
	"github.com/redis/go-redis/v9"
)

type standings map[string]database.ClientStanding

func (known standings) GetClientStanding(_ context.Context, clientID string) (*database.ClientStanding, error) {
	standing, found := known[clientID]
	if !found {
		return nil, database.ErrNotFound
	}
	return &standing, nil
}

type fixture struct {
	redis    *miniredis.Miniredis
	counter  *ratelimit.RedisCounter
	limiter  *ratelimit.Limiter
	standing standings
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	server := miniredis.RunT(t)
	counter := ratelimit.NewRedisCounter(redis.NewClient(&redis.Options{Addr: server.Addr()}))
	known := standings{}
	return &fixture{redis: server, counter: counter, limiter: ratelimit.New(counter, counter, known), standing: known}
}

func (fx *fixture) call(clientID string, userID string, method string, path string) *httptest.ResponseRecorder {
	handler := fx.limiter.Authenticated(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(method, path, nil)
	principal := access.Principal{UserID: userID, ClientID: clientID}
	request = request.WithContext(middleware.ContextWithPrincipal(request.Context(), principal))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func (fx *fixture) callUntilLimited(clientID string, userID string, method string, path string, ceiling int) (int, *httptest.ResponseRecorder) {
	for count := 1; count <= ceiling; count++ {
		response := fx.call(clientID, userID, method, path)
		if response.Code == http.StatusTooManyRequests {
			return count - 1, response
		}
	}
	return ceiling, nil
}

func TestPushIsLimitedPerUserOfAClientWithRetryAfter(t *testing.T) {
	fx := newFixture(t)
	fx.standing["notes"] = database.ClientStanding{ReviewStatus: database.ReviewStatusNone}
	allowed, limited := fx.callUntilLimited("notes", "user-a", http.MethodPost, "/api/v1/nodes/push", 1000)
	if allowed != ratelimit.DefaultLimits[ratelimit.BucketPush].PerUserClient || limited == nil {
		t.Fatalf("allowed %d calls before the limit, want %d", allowed, ratelimit.DefaultLimits[ratelimit.BucketPush].PerUserClient)
	}
	seconds, err := strconv.Atoi(limited.Header().Get("Retry-After"))
	if err != nil || seconds < 1 || seconds > 60 {
		t.Fatalf("Retry-After %q", limited.Header().Get("Retry-After"))
	}
	if other := fx.call("notes", "user-b", http.MethodPost, "/api/v1/nodes/push"); other.Code != http.StatusNoContent {
		t.Fatalf("another user of the client is not limited: %d", other.Code)
	}
	if sync := fx.call("notes", "user-a", http.MethodGet, "/api/v1/nodes/pull"); sync.Code != http.StatusNoContent {
		t.Fatalf("sync has its own limit: %d", sync.Code)
	}
}

func TestTheWindowEndsAndCountingStartsAgain(t *testing.T) {
	fx := newFixture(t)
	_, limited := fx.callUntilLimited("notes", "user-a", http.MethodPost, "/api/v1/nodes/push", 1000)
	if limited == nil {
		t.Fatal("never limited")
	}
	fx.redis.FastForward(ratelimit.Window + time.Second)
	if response := fx.call("notes", "user-a", http.MethodPost, "/api/v1/nodes/push"); response.Code != http.StatusNoContent {
		t.Fatalf("after the window: %d", response.Code)
	}
}

func TestVerifiedAndReviewedAppsGetHigherLimits(t *testing.T) {
	fx := newFixture(t)
	fx.standing["plain"] = database.ClientStanding{ReviewStatus: database.ReviewStatusNone}
	fx.standing["verified"] = database.ClientStanding{Verified: true, ReviewStatus: database.ReviewStatusNone}
	fx.standing["both"] = database.ClientStanding{Verified: true, ReviewStatus: database.ReviewStatusApproved}
	base := ratelimit.DefaultLimits[ratelimit.BucketPush].PerUserClient
	for clientID, want := range map[string]int{"plain": base, "verified": base * 2, "both": base * 4} {
		allowed, _ := fx.callUntilLimited(clientID, "user", http.MethodPost, "/api/v1/nodes/push", base*5)
		if allowed != want {
			t.Errorf("%s: allowed %d want %d", clientID, allowed, want)
		}
	}
}

func TestAnOperatorMultiplierOverridesTheStanding(t *testing.T) {
	multiplier := 0.5
	standing := database.ClientStanding{Verified: true, Multiplier: &multiplier}
	if got := ratelimit.MultiplierFor(&standing); got != 0.5 {
		t.Errorf("multiplier %v want 0.5", got)
	}
	if got := ratelimit.MultiplierFor(&database.ClientStanding{FirstParty: true}); got != ratelimit.MultiplierOfficial {
		t.Errorf("first party multiplier %v", got)
	}
}

func TestSuspendedAppsAreRefusedBeforeCounting(t *testing.T) {
	fx := newFixture(t)
	fx.standing["bad"] = database.ClientStanding{ReviewStatus: database.ReviewStatusSuspended}
	response := fx.call("bad", "user", http.MethodGet, "/api/v1/settings")
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "app_suspended") {
		t.Fatalf("suspended app: %d %s", response.Code, response.Body.String())
	}
}

func TestCountersAreSharedBetweenInstances(t *testing.T) {
	fx := newFixture(t)
	second := ratelimit.New(fx.counter, fx.counter, fx.standing)
	allowed, _ := fx.callUntilLimited("notes", "user", http.MethodPost, "/api/v1/nodes/push", 1000)
	handler := second.Authenticated(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	request := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/push", nil)
	request = request.WithContext(middleware.ContextWithPrincipal(request.Context(), access.Principal{UserID: "user", ClientID: "notes"}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if allowed == 0 || recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("a second limiter on the same Redis must see the same count: %d", recorder.Code)
	}
}

func TestAnonymousCallersAreLimitedByIP(t *testing.T) {
	fx := newFixture(t)
	handler := fx.limiter.ByIP(ratelimit.BucketPublic)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	limit := ratelimit.DefaultLimits[ratelimit.BucketPublic].PerIP
	serve := func(address string) int {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/schemas", nil)
		request.RemoteAddr = address
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder.Code
	}
	for count := 0; count < limit; count++ {
		if code := serve("203.0.113.9:4000"); code != http.StatusNoContent {
			t.Fatalf("call %d: %d", count, code)
		}
	}
	if code := serve("203.0.113.9"); code != http.StatusTooManyRequests {
		t.Fatalf("over the IP limit: %d", code)
	}
	if code := serve("203.0.113.10:4000"); code != http.StatusNoContent {
		t.Fatalf("another IP: %d", code)
	}
}

type brokenCounter struct{}

func (brokenCounter) Hit(context.Context, string, time.Duration) (int64, time.Duration, error) {
	return 0, 0, errors.New("redis down")
}

func (brokenCounter) Peek(context.Context, string) (int64, time.Duration, error) {
	return 0, 0, errors.New("redis down")
}

func (brokenCounter) Record(context.Context, string, bool) error { return errors.New("redis down") }

func (brokenCounter) Daily(context.Context, string, int) ([]ratelimit.DayCount, error) {
	return nil, errors.New("redis down")
}

func TestCallsGoThroughWhenRedisIsDown(t *testing.T) {
	limiter := ratelimit.New(brokenCounter{}, brokenCounter{}, standings{})
	handler := limiter.Authenticated(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/settings", nil)
	request = request.WithContext(middleware.ContextWithPrincipal(request.Context(), access.Principal{UserID: "u", ClientID: "c"}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("redis down: %d", recorder.Code)
	}
}

func TestUsageCountsRequestsAndRefusalsPerDay(t *testing.T) {
	fx := newFixture(t)
	allowed, _ := fx.callUntilLimited("notes", "user", http.MethodPost, "/api/v1/nodes/push", 1000)
	fx.call("notes", "user", http.MethodPost, "/api/v1/nodes/push")
	days, err := fx.counter.Daily(context.Background(), "notes", 3)
	if err != nil || len(days) != 3 {
		t.Fatalf("daily: %v %v", days, err)
	}
	today := days[2]
	if today.Requests != int64(allowed)+2 || today.RateLimited != 2 || days[0].Requests != 0 {
		t.Fatalf("today %+v after %d allowed calls; earlier %+v", today, allowed, days[0])
	}
}

func TestCountersCountHitsAndPeekWithoutCounting(t *testing.T) {
	server := miniredis.RunT(t)
	redisCounter := ratelimit.NewRedisCounter(redis.NewClient(&redis.Options{Addr: server.Addr()}))
	for name, counter := range map[string]ratelimit.Counter{"redis": redisCounter, "memory": ratelimit.NewMemoryCounter()} {
		ctx := context.Background()
		if count, _, err := counter.Peek(ctx, "key"); err != nil || count != 0 {
			t.Fatalf("%s: peek before any hit: %d %v", name, count, err)
		}
		counter.Hit(ctx, "key", time.Minute)
		count, remaining, err := counter.Hit(ctx, "key", time.Minute)
		if err != nil || count != 2 || remaining <= 0 || remaining > time.Minute {
			t.Fatalf("%s: second hit: %d %v %v", name, count, remaining, err)
		}
		if peeked, _, _ := counter.Peek(ctx, "key"); peeked != 2 {
			t.Fatalf("%s: peek counted: %d", name, peeked)
		}
	}
}

func TestMemoryCountersStartAgainAfterTheWindow(t *testing.T) {
	counter := ratelimit.NewMemoryCounter()
	ctx := context.Background()
	counter.Hit(ctx, "key", 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	if count, _, _ := counter.Hit(ctx, "key", time.Minute); count != 1 {
		t.Fatalf("after the window: %d", count)
	}
}
