package database

import (
	"context"
	"testing"
	"time"
)

func TestTargetCachePutGetInvalidate(t *testing.T) {
	c := newTargetCache(time.Minute)
	if _, ok := c.get("a"); ok {
		t.Fatal("empty cache returned a hit")
	}
	c.put("a", tenantRoute{target: surrealTarget{Endpoint: "ws://x"}})
	got, ok := c.get("a")
	if !ok || got.target.Endpoint != "ws://x" {
		t.Fatalf("get after put = (%+v, %v)", got, ok)
	}
	c.invalidate("a")
	if _, ok := c.get("a"); ok {
		t.Fatal("get after invalidate returned a hit")
	}
}

func TestTargetCacheExpiry(t *testing.T) {
	c := newTargetCache(10 * time.Millisecond)
	c.put("a", tenantRoute{target: surrealTarget{Endpoint: "ws://x"}})
	time.Sleep(25 * time.Millisecond)
	if _, ok := c.get("a"); ok {
		t.Fatal("expired entry was returned")
	}
}

// A cached route short-circuits resolution, so targetForNamespace returns its
// target without touching the control plane.
func TestTargetForNamespaceUsesCache(t *testing.T) {
	s := &SurrealStore{targets: newTargetCache(time.Minute)}
	want := surrealTarget{Endpoint: "ws://org-a:8000", User: "root", Pass: "secret"}
	s.targets.put("acme", tenantRoute{target: want, plan: "pro"})
	got, err := s.targetForNamespace(context.Background(), "client_acme")
	if err != nil {
		t.Fatalf("targetForNamespace: %v", err)
	}
	if got != want {
		t.Fatalf("targetForNamespace = %+v, want %+v", got, want)
	}
}

// A free-plan client with no dedicated instance routes to the shared target.
func TestRouteForNamespaceFreeUsesSharedTarget(t *testing.T) {
	shared := surrealTarget{Endpoint: "ws://shared:8000", User: "root", Pass: "secret"}
	s := &SurrealStore{targets: newTargetCache(time.Minute), sharedTenant: shared}
	s.targets.put("acme", tenantRoute{target: shared, plan: "free", shared: true})
	route, err := s.routeForNamespace(context.Background(), "client_acme")
	if err != nil {
		t.Fatalf("routeForNamespace: %v", err)
	}
	if route.target != shared || !route.shared || route.plan != "free" {
		t.Fatalf("routeForNamespace = %+v, want shared free target", route)
	}
}
