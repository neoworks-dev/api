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
	c.put("a", surrealTarget{Endpoint: "ws://x"})
	got, ok := c.get("a")
	if !ok || got.Endpoint != "ws://x" {
		t.Fatalf("get after put = (%+v, %v)", got, ok)
	}
	c.invalidate("a")
	if _, ok := c.get("a"); ok {
		t.Fatal("get after invalidate returned a hit")
	}
}

func TestTargetCacheExpiry(t *testing.T) {
	c := newTargetCache(10 * time.Millisecond)
	c.put("a", surrealTarget{Endpoint: "ws://x"})
	time.Sleep(25 * time.Millisecond)
	if _, ok := c.get("a"); ok {
		t.Fatal("expired entry was returned")
	}
}

// A cached target short-circuits resolution, so targetForNamespace returns it
// without touching the control plane.
func TestTargetForNamespaceUsesCache(t *testing.T) {
	s := &SurrealStore{targets: newTargetCache(time.Minute)}
	want := surrealTarget{Endpoint: "ws://org-a:8000", User: "root", Pass: "secret"}
	s.targets.put("acme", want)
	got, err := s.targetForNamespace(context.Background(), "client_acme")
	if err != nil {
		t.Fatalf("targetForNamespace: %v", err)
	}
	if got != want {
		t.Fatalf("targetForNamespace = %+v, want %+v", got, want)
	}
}
