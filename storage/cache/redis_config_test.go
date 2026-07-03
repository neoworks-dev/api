package cache

import (
	"reflect"
	"testing"
)

func TestConfigFromEnvSingleNode(t *testing.T) {
	t.Setenv("REDIS_URL", "cache.internal:6379")
	// Ensure sentinel vars are absent for this case.
	t.Setenv("REDIS_SENTINEL_ADDRS", "")
	t.Setenv("REDIS_MASTER_NAME", "")

	config := ConfigFromEnv()

	if config.Addr != "cache.internal:6379" {
		t.Fatalf("Addr = %q, want cache.internal:6379", config.Addr)
	}
	if len(config.SentinelAddrs) != 0 {
		t.Fatalf("SentinelAddrs = %v, want empty", config.SentinelAddrs)
	}
}

func TestConfigFromEnvSentinel(t *testing.T) {
	t.Setenv("REDIS_SENTINEL_ADDRS", "rfs-neoworks-redis:26379, 10.0.0.2:26379 ,")
	t.Setenv("REDIS_MASTER_NAME", "mymaster")

	config := ConfigFromEnv()

	want := []string{"rfs-neoworks-redis:26379", "10.0.0.2:26379"}
	if !reflect.DeepEqual(config.SentinelAddrs, want) {
		t.Fatalf("SentinelAddrs = %v, want %v (whitespace trimmed, empties dropped)", config.SentinelAddrs, want)
	}
	if config.MasterName != "mymaster" {
		t.Fatalf("MasterName = %q, want mymaster", config.MasterName)
	}
}

// NewRedisStore must build a client for both topologies without panicking. The
// underlying type is *redis.Client in both cases, so we assert on non-nil rather
// than on the branch taken.
func TestNewRedisStoreBothTopologies(t *testing.T) {
	single := NewRedisStore(Config{Addr: "127.0.0.1:6379"})
	if single == nil || single.client == nil {
		t.Fatal("single-node store or client is nil")
	}

	sentinel := NewRedisStore(Config{
		SentinelAddrs: []string{"rfs-neoworks-redis:26379"},
		MasterName:    "mymaster",
	})
	if sentinel == nil || sentinel.client == nil {
		t.Fatal("sentinel store or client is nil")
	}
}
