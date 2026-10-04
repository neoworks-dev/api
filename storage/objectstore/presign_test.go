package objectstore_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/neoworks/auth/storage/objectstore"
)

func TestPresignedURLsPointAtThePublicEndpointWithoutNetworkAccess(t *testing.T) {
	store, err := objectstore.New("internal.invalid:9000", "key", "secret", "bucket", false)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.UsePublicEndpoint("s3.public.test", "key", "secret", true); err != nil {
		t.Fatalf("public endpoint: %v", err)
	}

	for name, presign := range map[string]func(context.Context, string, time.Duration) (string, error){
		"put": store.PresignPut,
		"get": store.PresignGet,
	} {
		signed, err := presign(context.Background(), "3f2a/0", 15*time.Minute)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		parsed, err := url.Parse(signed)
		if err != nil {
			t.Fatalf("%s: parse %q: %v", name, signed, err)
		}
		if parsed.Scheme != "https" || parsed.Host != "s3.public.test" || parsed.Path != "/bucket/3f2a/0" {
			t.Errorf("%s: unexpected URL %s", name, signed)
		}
		if parsed.Query().Get("X-Amz-Expires") != "900" || parsed.Query().Get("X-Amz-Signature") == "" {
			t.Errorf("%s: URL is not a presigned URL: %s", name, signed)
		}
	}
}
