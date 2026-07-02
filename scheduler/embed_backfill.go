package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/neoworks/auth/embeddings"
	"github.com/neoworks/auth/storage/database"
)

// EmbedBackfillScheduler periodically embeds memory chunks that the synchronous
// ingestion path could not (the model server was down), retries failed chunks
// under a cap, and re-embeds stale chunks whose vectors came from a different
// model than the current deployment tier.
//
// Lifecycle state lives in the memory_chunk.status column, so a restart simply
// re-scans pending work — no in-memory watermark to lose.
type EmbedBackfillScheduler struct {
	store      *database.SurrealStore
	embedder   embeddings.Embedder
	interval   time.Duration
	batchSize  int
	maxRetries int
}

func NewEmbedBackfillScheduler(store *database.SurrealStore, embedder embeddings.Embedder) *EmbedBackfillScheduler {
	return &EmbedBackfillScheduler{
		store:      store,
		embedder:   embedder,
		interval:   2 * time.Minute,
		batchSize:  32,
		maxRetries: 5,
	}
}

// Start launches the ticker loop in its own goroutine. It is a no-op when no
// model server is configured (nothing could be embedded anyway).
func (s *EmbedBackfillScheduler) Start(ctx context.Context) {
	if !s.embedder.Available() {
		slog.Info("embed backfill disabled (no model server configured)")
		return
	}
	go s.loop(ctx)
}

func (s *EmbedBackfillScheduler) loop(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.tick(ctx); err != nil {
				slog.Error("embed backfill tick", "err", err)
			}
		}
	}
}

// tick embeds one batch of outstanding chunks. The batch is rate-limited by
// batchSize so a mass re-embed (e.g. a tier change) does not peg the model server.
func (s *EmbedBackfillScheduler) tick(ctx context.Context) error {
	refs, err := s.store.Memories.ListEmbeddableChunks(ctx, s.embedder.Model(), s.maxRetries, s.batchSize)
	if err != nil {
		return err
	}
	if len(refs) == 0 {
		return nil
	}

	texts := make([]string, len(refs))
	for i, ref := range refs {
		texts[i] = ref.Content
	}

	vectors, err := s.embedder.EmbedDocuments(ctx, texts)
	if err != nil || len(vectors) != len(refs) {
		// The whole batch failed; bump each chunk's retry counter so a persistently
		// bad chunk is eventually dropped from the queue.
		for _, ref := range refs {
			if markErr := s.store.Memories.MarkChunkFailed(ctx, ref.ID); markErr != nil {
				slog.Error("embed backfill mark failed", "chunk", ref.ID, "err", markErr)
			}
		}
		if err != nil {
			return err
		}
		return nil
	}

	model, dim := s.embedder.Model(), s.embedder.Dimension()
	for i, ref := range refs {
		if setErr := s.store.Memories.SetChunkVector(ctx, ref.ID, vectors[i], model, dim); setErr != nil {
			slog.Error("embed backfill set vector", "chunk", ref.ID, "err", setErr)
		}
	}
	return nil
}
