package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/neoworks/auth/storage/database"
)

// SpacePurgeScheduler deletes tombstoned space items past the retention window
// and advances each space's purge horizon, so sync cursors older than the
// horizon get told to full-resync instead of silently missing deletes.
type SpacePurgeScheduler struct {
	store     *database.SurrealStore
	interval  time.Duration
	retention time.Duration
}

func NewSpacePurgeScheduler(store *database.SurrealStore) *SpacePurgeScheduler {
	return &SpacePurgeScheduler{
		store:     store,
		interval:  24 * time.Hour,
		retention: 90 * 24 * time.Hour,
	}
}

func (s *SpacePurgeScheduler) Start(ctx context.Context) {
	go s.loop(ctx)
}

func (s *SpacePurgeScheduler) loop(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			purged, err := s.store.Spaces.PurgeTombstones(ctx, s.retention)
			if err != nil {
				slog.Error("space tombstone purge", "err", err)
				continue
			}
			if purged > 0 {
				slog.Info("space tombstone purge", "purged", purged)
			}
		}
	}
}
