// Package scheduler runs the API's background jobs.
package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/neoworks/auth/storage/database"
)

const (
	defaultTombstoneRetention = 30 * 24 * time.Hour
	purgeInterval             = time.Hour
	removeTimeout             = 2 * time.Minute
)

// ObjectRemover deletes every stored chunk of a blob object.
type ObjectRemover interface {
	RemovePrefix(ctx context.Context, prefix string) error
}

// TombstonePurger removes tombstones past the retention window, raises the
// owners' purge horizons and deletes the chunks nothing references any more.
type TombstonePurger struct {
	store     *database.SurrealStore
	objects   ObjectRemover
	retention time.Duration
}

// NewTombstonePurger builds the job. A retention of zero or less uses 30 days.
func NewTombstonePurger(store *database.SurrealStore, objects ObjectRemover, retention time.Duration) *TombstonePurger {
	if retention <= 0 {
		retention = defaultTombstoneRetention
	}
	return &TombstonePurger{store: store, objects: objects, retention: retention}
}

// Start runs the job once an hour until ctx ends.
func (purger *TombstonePurger) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(purgeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				purger.RunOnce(ctx)
			}
		}
	}()
}

// RunOnce performs one purge pass.
func (purger *TombstonePurger) RunOnce(ctx context.Context) {
	result, err := purger.store.PurgeTombstones(ctx, purger.retention)
	if err != nil {
		slog.Error("purge tombstones", "error", err)
		return
	}
	if result.Nodes > 0 {
		slog.Info("purged tombstones", "nodes", result.Nodes, "objects", len(result.UnreferencedObjects))
	}
	purger.removeObjects(ctx, result.UnreferencedObjects)
}

func (purger *TombstonePurger) removeObjects(ctx context.Context, objectIDs []string) {
	for _, objectID := range objectIDs {
		removeContext, cancel := context.WithTimeout(ctx, removeTimeout)
		err := purger.objects.RemovePrefix(removeContext, objectID+"/")
		cancel()
		if err != nil {
			slog.Error("remove blob object", "objectId", objectID, "error", err)
		}
	}
}
