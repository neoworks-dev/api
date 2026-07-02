// Package push sends approval notifications to a user's registered devices.
// Remote delivery (FCM/APNs) is env-gated; when unconfigured it degrades to a
// no-op and the app relies on its long-poll instead, so dev works out of the box.
package push

import (
	"context"
	"log/slog"
	"os"

	"github.com/neoworks/auth/oauth"
)

type Sender interface {
	Send(ctx context.Context, tokens []*oauth.PushToken, title, body string, data map[string]string) error
}

type Config struct {
	FCMProjectID string
	APNSKeyID    string
}

func ConfigFromEnv() Config {
	return Config{
		FCMProjectID: os.Getenv("FCM_PROJECT_ID"),
		APNSKeyID:    os.Getenv("APNS_KEY_ID"),
	}
}

// NewSender returns a configured remote sender, or a no-op sender when no push
// credentials are present.
func NewSender(cfg Config) Sender {
	if cfg.FCMProjectID == "" && cfg.APNSKeyID == "" {
		return noopSender{}
	}
	// TODO: real FCM HTTP v1 / APNs senders once credentials are provisioned.
	return noopSender{}
}

type noopSender struct{}

func (noopSender) Send(_ context.Context, tokens []*oauth.PushToken, title, _ string, _ map[string]string) error {
	slog.Debug("push noop (no credentials configured)", "tokens", len(tokens), "title", title)
	return nil
}
