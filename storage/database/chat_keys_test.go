package database

import (
	"context"
	"fmt"
	"testing"

	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// TestChatPrekeyBundles covers the X3DH keystore: a device publishes its identity,
// signed prekey, and a one-time prekey pool; a bundle fetch returns one bundle per
// the target's identity-bearing device; and each fetch pops a distinct one-time
// prekey until the pool empties, after which bundles omit it.
// Requires the dev SurrealDB with migration 032 applied; skipped if unreachable.
func TestChatPrekeyBundles(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")

	suffix := randSuffix()
	ownerID := "chat_user_" + suffix
	mustQuery(t, root, "CREATE type::record('user', $id) SET first_name = 'U', last_name = 'U', email = $e, password_hash = 'x'",
		map[string]any{"id": ownerID, "e": ownerID + "@test.local"})

	t.Cleanup(func() {
		u := models.NewRecordID("user", ownerID)
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE chat_onetime_prekey WHERE device.user = $u", map[string]any{"u": u})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE chat_signed_prekey WHERE device.user = $u", map[string]any{"u": u})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE device WHERE user = $u", map[string]any{"u": u})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": u})
	})

	// Register a device, then publish its chat identity + prekeys.
	devicePubKey := "devpub_" + suffix
	if _, err := store.RegisterDevice(ctx, &RegisterDeviceParams{
		UserID:     ownerID,
		PublicKey:  devicePubKey,
		WrappedAMK: "wrapped",
	}); err != nil {
		t.Fatalf("register device: %v", err)
	}

	device, err := store.GetDeviceByPublicKey(ctx, ownerID, devicePubKey)
	if err != nil {
		t.Fatalf("get device: %v", err)
	}
	deviceID := fmt.Sprintf("%v", device.ID.ID)

	if err := store.SetDeviceChatIdentity(ctx, ownerID, devicePubKey, "identity_pub", "signing_pub"); err != nil {
		t.Fatalf("set identity: %v", err)
	}
	if err := store.PublishSignedPrekey(ctx, deviceID, SignedPrekey{KeyID: 1, PublicKey: "spk_pub", Signature: "sig"}); err != nil {
		t.Fatalf("publish signed prekey: %v", err)
	}
	if err := store.AddOneTimePrekeys(ctx, deviceID, []OneTimePrekey{
		{KeyID: 1, PublicKey: "otpk_1"},
		{KeyID: 2, PublicKey: "otpk_2"},
	}); err != nil {
		t.Fatalf("add one-time prekeys: %v", err)
	}

	count, err := store.CountOneTimePrekeys(ctx, deviceID)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 2 {
		t.Fatalf("want 2 one-time prekeys, got %d", count)
	}

	// First two bundle fetches each pop a distinct one-time prekey.
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		bundles, err := store.GetPrekeyBundles(ctx, ownerID)
		if err != nil {
			t.Fatalf("bundle %d: %v", i, err)
		}
		if len(bundles) != 1 {
			t.Fatalf("bundle %d: want 1 device bundle, got %d", i, len(bundles))
		}
		b := bundles[0]
		if b.IdentityKey != "identity_pub" || b.SigningKey != "signing_pub" {
			t.Fatalf("bundle %d: identity keys not returned: %+v", i, b)
		}
		if b.SignedPrekey == nil || b.SignedPrekey.PublicKey != "spk_pub" {
			t.Fatalf("bundle %d: signed prekey missing: %+v", i, b)
		}
		if b.OneTimePrekey == nil {
			t.Fatalf("bundle %d: expected a one-time prekey", i)
		}
		if seen[b.OneTimePrekey.PublicKey] {
			t.Fatalf("one-time prekey %q handed out twice", b.OneTimePrekey.PublicKey)
		}
		seen[b.OneTimePrekey.PublicKey] = true
	}

	// Pool now empty: bundle still returned, but without a one-time prekey.
	bundles, err := store.GetPrekeyBundles(ctx, ownerID)
	if err != nil {
		t.Fatalf("bundle (empty pool): %v", err)
	}
	if len(bundles) != 1 {
		t.Fatalf("want 1 bundle, got %d", len(bundles))
	}
	if bundles[0].OneTimePrekey != nil {
		t.Fatalf("expected no one-time prekey after pool exhausted, got %+v", bundles[0].OneTimePrekey)
	}
}
