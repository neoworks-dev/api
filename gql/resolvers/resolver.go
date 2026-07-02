package gql

import (
	"context"

	"github.com/neoworks/auth/dataplane"
	"github.com/neoworks/auth/email"
	"github.com/neoworks/auth/embeddings"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/push"
	"github.com/neoworks/auth/storage/database"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// searchEmbeddingModeKey is the per-user setting that selects where a search
// query is embedded: "server" (the configured model server) or "client" (the
// browser supplies a precomputed vector). Absent or unrecognized → "server".
const searchEmbeddingModeKey = "search_embedding_mode"

type Resolver struct {
	store    *database.SurrealStore
	mailer   email.Sender
	pusher   push.Sender
	engine   *dataplane.Engine
	embedder embeddings.Embedder
}

func NewGqlResolver(db *database.SurrealStore, mailer email.Sender, pusher push.Sender, engine *dataplane.Engine, embedder embeddings.Embedder) *Resolver {
	return &Resolver{
		store:    db,
		mailer:   mailer,
		pusher:   pusher,
		engine:   engine,
		embedder: embedder,
	}
}

// resolveQueryVector produces the vector arm for a hybrid search, honoring the
// caller's search_embedding_mode. In "client" mode it normalizes the
// browser-supplied vector to the stored dimension; otherwise it embeds the query
// text server-side when a model server is configured. A nil result means "no
// vector arm" — the lexical (BM25) arm still runs.
func (r *Resolver) resolveQueryVector(ctx context.Context, claim *oauth.Claims, query string, clientVector []float64) []float32 {
	if r.searchEmbeddingMode(ctx, claim) == "client" {
		if len(clientVector) == 0 {
			return nil
		}
		vec := make([]float32, len(clientVector))
		for i, value := range clientVector {
			vec[i] = float32(value)
		}
		return embeddings.Normalize(vec, r.embedder.Dimension())
	}

	if r.embedder.Available() {
		if vec, err := r.embedder.EmbedQuery(ctx, query); err == nil {
			return vec
		}
	}
	return nil
}

func (r *Resolver) searchEmbeddingMode(ctx context.Context, claim *oauth.Claims) string {
	setting, err := r.store.Settings.Get(ctx, models.NewRecordID("user", claim.Subject), claim.ClientID, searchEmbeddingModeKey)
	if err == nil && setting != nil && setting.Value == "client" {
		return "client"
	}
	return "server"
}

