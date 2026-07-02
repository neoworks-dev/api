package gql

import (
	"context"

	"github.com/neoworks/auth/embeddings"
	"github.com/neoworks/auth/storage/database"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// memoryOrg resolves an optional organization id, verifying the caller belongs to
// it. Returns nil when no organization is given (a personal memory).
func (r *mutationResolver) memoryOrg(ctx context.Context, subject string, orgID *string) (*models.RecordID, error) {
	if orgID == nil {
		return nil, nil
	}
	org := models.NewRecordID("organization", *orgID)
	if !r.callerIsMember(ctx, subject, org) {
		return nil, Public("forbidden: not a member of this organization")
	}
	return &org, nil
}

// reindexMemory chunks the source text, embeds each chunk when a model server is
// available, and replaces the memory's chunk set. When the embedder is down (or
// errors) chunks are stored as pending and the backfill worker fills them later —
// ingestion never fails because embedding is unavailable.
func (r *mutationResolver) reindexMemory(ctx context.Context, memoryID, userID models.RecordID, sourceText string) error {
	pieces := embeddings.NewCharChunker().Chunk(sourceText)
	if len(pieces) == 0 {
		return r.store.Memories.ReplaceChunks(ctx, memoryID, userID, nil)
	}

	var vectors []embeddings.Vector
	if r.embedder.Available() {
		texts := make([]string, len(pieces))
		for i, p := range pieces {
			texts[i] = p.Content
		}
		if vs, err := r.embedder.EmbedDocuments(ctx, texts); err == nil && len(vs) == len(pieces) {
			vectors = vs
		}
	}

	chunks := make([]database.ChunkData, len(pieces))
	for i, p := range pieces {
		chunks[i] = database.ChunkData{Idx: i, Content: p.Content, Start: p.Start, End: p.End}
		if vectors != nil {
			chunks[i].Embedding = vectors[i]
			chunks[i].Model = r.embedder.Model()
			chunks[i].Dim = r.embedder.Dimension()
		}
	}
	return r.store.Memories.ReplaceChunks(ctx, memoryID, userID, chunks)
}
