// Package changes streams a live change feed over server-sent events. Each API
// instance watches node and grant changes in the database once and fans them
// out to the signed-in clients connected to it; an event only says that a
// collection changed and at which sequence, so clients pull the content
// themselves. The wire format is documented in neoworks.dev#57.
package changes

import (
	"context"

	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/storage/database"
)

// Feed is what the hub needs from the database.
type Feed interface {
	WatchFeed(ctx context.Context) (Watch, error)
	FeedRecipients(ctx context.Context, change database.FeedChange) ([]database.FeedRecipient, error)
	FeedHead(ctx context.Context) (int64, error)
	HasChangesSince(ctx context.Context, principal access.Principal, cursor int64) (bool, error)
}

// Watch is a running subscription to the database's changes.
type Watch interface {
	Changes() <-chan database.FeedChange
	Lost() <-chan struct{}
	Close()
}

// StoreFeed serves a Feed from the database store.
type StoreFeed struct {
	*database.SurrealStore
}

func (feed StoreFeed) WatchFeed(ctx context.Context) (Watch, error) {
	return feed.SurrealStore.WatchFeed(ctx)
}
