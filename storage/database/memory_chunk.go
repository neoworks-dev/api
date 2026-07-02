package database

import (
	"context"
	"fmt"
	"sort"
	"strings"

	gql_model "github.com/neoworks/auth/gql/model"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// rrfK is the Reciprocal Rank Fusion constant; 60 is the value from the original
// RRF paper and a common default. Higher values flatten the contribution of rank.
const rrfK = 60

// ChunkData is one embeddable piece of a memory, ready to persist. A nil
// Embedding means the vector is not yet computed (status persists as pending).
type ChunkData struct {
	Idx       int
	Content   string
	Start     int
	End       int
	Embedding []float32
	Model     string
	Dim       int
}

// ChunkRef identifies a chunk that still needs embedding (pending/failed/stale),
// returned to the backfill worker.
type ChunkRef struct {
	ID      models.RecordID
	Content string
}

type dbChunkRef struct {
	ID      *models.RecordID `json:"id,omitempty"`
	Content *string          `json:"content,omitempty"`
}

// ReplaceChunks deletes any existing chunks for a memory and inserts the given
// set in one transaction. Used on (re)ingestion so a memory's chunk set is always
// consistent with its current source.
func (store *MemoryStore) ReplaceChunks(ctx context.Context, memoryID, userID models.RecordID, chunks []ChunkData) error {
	statements := []string{"DELETE memory_chunk WHERE memory = $memory AND user = $user;"}
	params := map[string]any{"memory": memoryID, "user": userID}

	for i, ch := range chunks {
		fields := []string{
			fmt.Sprintf("memory = $memory, user = $user, idx = $idx_%d", i),
			fmt.Sprintf("content = $content_%d", i),
			fmt.Sprintf("span = $span_%d", i),
		}
		params[fmt.Sprintf("idx_%d", i)] = ch.Idx
		params[fmt.Sprintf("content_%d", i)] = ch.Content
		params[fmt.Sprintf("span_%d", i)] = map[string]any{"start": ch.Start, "end": ch.End}

		if ch.Embedding != nil {
			fields = append(fields,
				fmt.Sprintf("embedding = $embedding_%d", i),
				fmt.Sprintf("model = $model_%d", i),
				fmt.Sprintf("dim = $dim_%d", i),
				"status = 'ready'",
			)
			params[fmt.Sprintf("embedding_%d", i)] = ch.Embedding
			params[fmt.Sprintf("model_%d", i)] = ch.Model
			params[fmt.Sprintf("dim_%d", i)] = ch.Dim
		} else {
			fields = append(fields, "status = 'pending'")
		}
		statements = append(statements, "CREATE memory_chunk SET "+strings.Join(fields, ", ")+";")
	}

	query := strings.Join(statements, "\n")
	if _, err := surrealdb.Query[[]any](ctx, store.DB, query, params); err != nil {
		return fmt.Errorf("replace chunks: %w", err)
	}
	return nil
}

// DropChunks removes all chunks (and their vectors) for a memory.
func (store *MemoryStore) DropChunks(ctx context.Context, memoryID, userID models.RecordID) error {
	_, err := surrealdb.Query[[]any](ctx, store.DB,
		"DELETE memory_chunk WHERE memory = $memory AND user = $user",
		map[string]any{"memory": memoryID, "user": userID},
	)
	if err != nil {
		return fmt.Errorf("drop chunks: %w", err)
	}
	return nil
}

// ListEmbeddableChunks returns chunks needing (re)embedding: pending, failed
// (under the retry cap), or stale (a different model than the current tier).
func (store *MemoryStore) ListEmbeddableChunks(ctx context.Context, currentModel string, maxRetries, limit int) ([]ChunkRef, error) {
	query := fmt.Sprintf(`
        SELECT id, content FROM memory_chunk
        WHERE content != NONE
          AND (
            status = 'pending'
            OR (status = 'failed' AND retry_count < $max_retries)
            OR (status = 'ready' AND model != $model)
          )
        LIMIT %d`, limit)
	results, err := surrealdb.Query[[]dbChunkRef](ctx, store.DB, query, map[string]any{
		"max_retries": maxRetries,
		"model":       currentModel,
	})
	if err != nil {
		return nil, fmt.Errorf("list embeddable chunks: %w", err)
	}
	for _, qr := range *results {
		out := make([]ChunkRef, 0, len(qr.Result))
		for _, r := range qr.Result {
			if r.ID == nil || r.Content == nil {
				continue
			}
			out = append(out, ChunkRef{ID: *r.ID, Content: *r.Content})
		}
		return out, nil
	}
	return nil, nil
}

// SetChunkVector marks a chunk ready with its computed embedding + provenance.
func (store *MemoryStore) SetChunkVector(ctx context.Context, chunkID models.RecordID, embedding []float32, model string, dim int) error {
	_, err := surrealdb.Query[[]any](ctx, store.DB, `
        UPDATE $id SET embedding = $embedding, model = $model, dim = $dim,
            status = 'ready', retry_count = 0`,
		map[string]any{"id": chunkID, "embedding": embedding, "model": model, "dim": dim},
	)
	if err != nil {
		return fmt.Errorf("set chunk vector: %w", err)
	}
	return nil
}

// MarkChunkFailed bumps the retry counter and flags the chunk failed so it is not
// hot-looped by the backfill worker.
func (store *MemoryStore) MarkChunkFailed(ctx context.Context, chunkID models.RecordID) error {
	_, err := surrealdb.Query[[]any](ctx, store.DB,
		"UPDATE $id SET status = 'failed', retry_count = retry_count + 1",
		map[string]any{"id": chunkID},
	)
	if err != nil {
		return fmt.Errorf("mark chunk failed: %w", err)
	}
	return nil
}

// ── Hybrid search ─────────────────────────────────────────────────────────────

type dbSearchRow struct {
	Memory  *models.RecordID `json:"memory,omitempty"`
	Content *string          `json:"content,omitempty"`
	Score   float64          `json:"score"`
}

// SearchMemories runs the vector and lexical arms over the caller's ready chunks
// and fuses them with Reciprocal Rank Fusion. queryVec may be nil when no embedder
// is configured — the lexical (BM25) arm still runs. Results are distinct parent
// memories ranked by fused score, each with its best-matching chunk as a snippet.
func (store *MemoryStore) SearchMemories(ctx context.Context, userID models.RecordID, queryVec []float32, queryText string, limit int) ([]*gql_model.MemorySearchHit, error) {
	if limit <= 0 {
		limit = 20
	}
	pool := limit * 4
	if pool < 20 {
		pool = 20
	}

	var vectorRows, lexicalRows []dbSearchRow
	var err error

	if len(queryVec) > 0 {
		// Exact brute-force cosine, user-scoped. This sidesteps the HNSW
		// post-filter recall problem for v1; the HNSW index backs scaling later.
		vectorRows, err = store.runSearch(ctx, fmt.Sprintf(`
            SELECT memory, content, vector::similarity::cosine(embedding, $q) AS score
            FROM memory_chunk
            WHERE user = $user AND status = 'ready' AND embedding != NONE
            ORDER BY score DESC LIMIT %d`, pool),
			map[string]any{"user": userID, "q": queryVec})
		if err != nil {
			return nil, err
		}
	}

	if strings.TrimSpace(queryText) != "" {
		lexicalRows, err = store.runSearch(ctx, fmt.Sprintf(`
            SELECT memory, content, search::score(1) AS score
            FROM memory_chunk
            WHERE user = $user AND content @1@ $query
            ORDER BY score DESC LIMIT %d`, pool),
			map[string]any{"user": userID, "query": queryText})
		if err != nil {
			return nil, err
		}
	}

	ranked := fuseRRF(vectorRows, lexicalRows, limit)
	if len(ranked) == 0 {
		return nil, nil
	}
	return store.loadSearchHits(ctx, userID, ranked)
}

func (store *MemoryStore) runSearch(ctx context.Context, query string, params map[string]any) ([]dbSearchRow, error) {
	results, err := surrealdb.Query[[]dbSearchRow](ctx, store.DB, query, params)
	if err != nil {
		return nil, fmt.Errorf("search memories: %w", err)
	}
	for _, qr := range *results {
		return qr.Result, nil
	}
	return nil, nil
}

type fusedHit struct {
	memoryID string
	score    float64
	snippet  string
}

// fuseRRF merges the two ranked arms by sum(1/(rrfK + rank)), grouping chunk rows
// to their parent memory and keeping the best chunk's text as the snippet.
func fuseRRF(vectorRows, lexicalRows []dbSearchRow, limit int) []fusedHit {
	scores := map[string]float64{}
	snippets := map[string]string{}

	accumulate := func(rows []dbSearchRow) {
		seen := map[string]bool{}
		rank := 0
		for _, r := range rows {
			if r.Memory == nil {
				continue
			}
			id := fmt.Sprintf("%v", r.Memory.ID)
			// Rank by chunk position, but a memory only scores once per arm (its
			// best chunk, since rows are pre-sorted by score).
			if seen[id] {
				continue
			}
			seen[id] = true
			rank++
			scores[id] += 1.0 / float64(rrfK+rank)
			if _, ok := snippets[id]; !ok && r.Content != nil {
				snippets[id] = *r.Content
			}
		}
	}
	accumulate(vectorRows)
	accumulate(lexicalRows)

	hits := make([]fusedHit, 0, len(scores))
	for id, score := range scores {
		hits = append(hits, fusedHit{memoryID: id, score: score, snippet: snippets[id]})
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].score == hits[j].score {
			return hits[i].memoryID < hits[j].memoryID
		}
		return hits[i].score > hits[j].score
	})
	if len(hits) > limit {
		hits = hits[:limit]
	}
	return hits
}

// loadSearchHits fetches the (non-deleted) memory rows for the ranked ids and
// assembles the hits in ranked order.
func (store *MemoryStore) loadSearchHits(ctx context.Context, userID models.RecordID, ranked []fusedHit) ([]*gql_model.MemorySearchHit, error) {
	ids := make([]models.RecordID, len(ranked))
	for i, h := range ranked {
		ids[i] = models.NewRecordID("memory", h.memoryID)
	}
	results, err := surrealdb.Query[[]dbMemory](ctx, store.DB,
		"SELECT * FROM memory WHERE id IN $ids AND user = $user AND deleted = false",
		map[string]any{"ids": ids, "user": userID},
	)
	if err != nil {
		return nil, fmt.Errorf("load search hits: %w", err)
	}

	byID := map[string]*gql_model.Memory{}
	for _, qr := range *results {
		for i := range qr.Result {
			m := memoryToGQL(&qr.Result[i])
			byID[m.ID] = m
		}
	}

	hits := make([]*gql_model.MemorySearchHit, 0, len(ranked))
	for _, h := range ranked {
		memory, ok := byID[h.memoryID]
		if !ok {
			continue // deleted between search and load
		}
		snippet := h.snippet
		hit := &gql_model.MemorySearchHit{Memory: memory, Score: h.score}
		if snippet != "" {
			hit.Snippet = &snippet
		}
		hits = append(hits, hit)
	}
	return hits, nil
}
