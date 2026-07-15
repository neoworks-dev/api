package database

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// dialThrottleRedis returns a client to the dev Redis, skipping the test when none
// is reachable so the suite stays green without external infra.
func dialThrottleRedis(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("REDIS_URL")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		t.Skipf("redis not reachable at %s: %v", addr, err)
	}
	return client
}

func TestRedisThrottlerCapAndRelease(t *testing.T) {
	client := dialThrottleRedis(t)
	defer client.Close() //nolint:errcheck
	ctx := context.Background()

	// Unique namespace per run so leftover leases never leak between tests.
	ns := "client_test_" + mustLeaseID(t)
	defer client.Del(ctx, tenantLeaseKey(ns), globalLeaseKey)

	throttle := NewRedisThrottler(client, ThrottleConfig{
		FreeCap:       2,
		ProCap:        2,
		PenaltyCap:    1,
		GlobalCap:     100,
		CostThreshold: 1e12, // effectively never penalize in this test
		CostHalfLife:  30 * time.Second,
		LeaseTTL:      30 * time.Second,
		MaxWait:       100 * time.Millisecond,
		Backoff:       10 * time.Millisecond,
	})

	// Fill the tenant's two slots.
	release1, err := throttle.Acquire(ctx, ns, "free")
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	release2, err := throttle.Acquire(ctx, ns, "free")
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}

	// Third acquire has no slot and must time out as busy.
	start := time.Now()
	if _, err := throttle.Acquire(ctx, ns, "free"); !errors.Is(err, ErrTenantBusy) {
		t.Fatalf("acquire 3 err = %v, want ErrTenantBusy", err)
	}
	if waited := time.Since(start); waited < 90*time.Millisecond {
		t.Fatalf("acquire 3 returned after %v, expected to queue ~MaxWait", waited)
	}

	// Freeing a slot lets the next query in.
	release1()
	release3, err := throttle.Acquire(ctx, ns, "free")
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	release2()
	release3()
}

// A busy tenant must not block a different tenant — the caps are per-namespace.
func TestRedisThrottlerIsolatesTenants(t *testing.T) {
	client := dialThrottleRedis(t)
	defer client.Close() //nolint:errcheck
	ctx := context.Background()

	nsA := "client_test_" + mustLeaseID(t)
	nsB := "client_test_" + mustLeaseID(t)
	defer client.Del(ctx, tenantLeaseKey(nsA), tenantLeaseKey(nsB), globalLeaseKey)

	throttle := NewRedisThrottler(client, ThrottleConfig{
		FreeCap:       1,
		ProCap:        1,
		PenaltyCap:    1,
		GlobalCap:     100,
		CostThreshold: 1e12,
		CostHalfLife:  30 * time.Second,
		LeaseTTL:      30 * time.Second,
		MaxWait:       50 * time.Millisecond,
		Backoff:       10 * time.Millisecond,
	})

	releaseA, err := throttle.Acquire(ctx, nsA, "free")
	if err != nil {
		t.Fatalf("acquire A: %v", err)
	}
	defer releaseA()

	// Tenant A is at its cap; tenant B must still be admitted immediately.
	releaseB, err := throttle.Acquire(ctx, nsB, "free")
	if err != nil {
		t.Fatalf("acquire B (should be independent of A): %v", err)
	}
	releaseB()
}

// A tenant that has run up a high recent cost is dropped to PenaltyCap, while a
// fresh tenant still gets the base cap — the noisy neighbour is throttled alone.
func TestRedisThrottlerPenalizesHeavyTenant(t *testing.T) {
	client := dialThrottleRedis(t)
	defer client.Close() //nolint:errcheck
	ctx := context.Background()

	heavy := "client_test_" + mustLeaseID(t)
	fresh := "client_test_" + mustLeaseID(t)
	defer client.Del(ctx,
		tenantLeaseKey(heavy), tenantCostKey(heavy),
		tenantLeaseKey(fresh), tenantCostKey(fresh),
		globalLeaseKey,
	)

	throttle := NewRedisThrottler(client, ThrottleConfig{
		FreeCap:       4,
		ProCap:        4,
		PenaltyCap:    1,
		GlobalCap:     100,
		CostThreshold: 5,                // 5ms of recent query time trips the penalty
		CostHalfLife:  10 * time.Minute, // negligible decay over the test
		LeaseTTL:      30 * time.Second,
		MaxWait:       50 * time.Millisecond,
		Backoff:       10 * time.Millisecond,
	})

	// Run up cost on the heavy tenant: hold a lease long enough to exceed the
	// threshold when folded into its score on release.
	release, err := throttle.Acquire(ctx, heavy, "free")
	if err != nil {
		t.Fatalf("heavy acquire: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	release()

	// The heavy tenant is now penalized to a cap of 1.
	held, err := throttle.Acquire(ctx, heavy, "free")
	if err != nil {
		t.Fatalf("heavy re-acquire (penalized cap still allows 1): %v", err)
	}
	defer held()
	if _, err := throttle.Acquire(ctx, heavy, "free"); !errors.Is(err, ErrTenantBusy) {
		t.Fatalf("heavy second acquire err = %v, want ErrTenantBusy (penalty cap 1)", err)
	}

	// A fresh tenant is unaffected — it keeps the base cap.
	f1, err := throttle.Acquire(ctx, fresh, "free")
	if err != nil {
		t.Fatalf("fresh acquire 1: %v", err)
	}
	f2, err := throttle.Acquire(ctx, fresh, "free")
	if err != nil {
		t.Fatalf("fresh acquire 2 (base cap should allow it): %v", err)
	}
	f1()
	f2()
}

func mustLeaseID(t *testing.T) string {
	t.Helper()
	id, err := newLeaseID()
	if err != nil {
		t.Fatalf("lease id: %v", err)
	}
	return id
}
