// Package embeddings turns text into vector embeddings for the memories feature.
// Like the email and push packages, it is env-gated: when no model server is
// configured it degrades to a no-op so dev works without a running embedder.
//
// The same OpenAI-compatible HTTP client serves both deployment tiers — only the
// base URL and model name change by env (CPU self-host = Qwen3-Embedding-0.6b via
// Ollama; GPU hosted = Qwen3-Embedding-8b via vLLM). Vectors from both tiers are
// truncated to a common dimension via Matryoshka so the SurrealDB HNSW index has a
// fixed DIMENSION, but they live in different vector spaces and must never be
// ranked together (the producing model is stamped onto each chunk).
package embeddings

import (
	"context"
	"errors"
	"math"
	"os"
	"strconv"
	"time"
)

// DefaultDimension is the Matryoshka truncation target and the HNSW DIMENSION.
// nomic-embed-text-v1.5 / nomic-embed-vision-v1.5 are natively 768-dim and share
// one space; EMBEDDINGS_DIMENSION can override.
const DefaultDimension = 768

// ErrUnavailable is returned by the no-op embedder when no model server is
// configured. Callers branch on Available() to fall back to pending chunks.
var ErrUnavailable = errors.New("embeddings: no model server configured")

// Vector is a single embedding; its length equals Embedder.Dimension().
type Vector []float32

// Embedder produces embeddings. Query and document embeddings use different
// instruction prefixes (asymmetric retrieval), so they are distinct methods even
// though they hit the same endpoint.
type Embedder interface {
	// EmbedQuery embeds a search query (wrapped with the retrieval instruction).
	EmbedQuery(ctx context.Context, text string) (Vector, error)
	// EmbedDocuments embeds raw passages in a single batched call.
	EmbedDocuments(ctx context.Context, texts []string) ([]Vector, error)
	// Model is the identifier stamped onto each chunk, e.g. "qwen3-embedding:0.6b".
	Model() string
	// Dimension is the stored vector length (after Matryoshka truncation).
	Dimension() int
	// Available reports whether a real model server is configured.
	Available() bool
}

type Config struct {
	URL       string
	Model     string
	APIKey    string
	Dimension int
	Timeout   time.Duration
	BatchSize int
}

func ConfigFromEnv() Config {
	return Config{
		URL:       os.Getenv("EMBEDDINGS_URL"),
		Model:     os.Getenv("EMBEDDINGS_MODEL"),
		APIKey:    os.Getenv("EMBEDDINGS_API_KEY"),
		Dimension: envInt("EMBEDDINGS_DIMENSION", DefaultDimension),
		Timeout:   time.Duration(envInt("EMBEDDINGS_TIMEOUT_SECONDS", 30)) * time.Second,
		BatchSize: envInt("EMBEDDINGS_BATCH_SIZE", 32),
	}
}

// NewClient returns an HTTP embedder when a URL is configured, otherwise a no-op
// embedder whose calls return ErrUnavailable.
func NewClient(cfg Config) Embedder {
	if cfg.URL == "" || cfg.Model == "" {
		return noopEmbedder{}
	}
	if cfg.Dimension <= 0 {
		cfg.Dimension = DefaultDimension
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 32
	}
	return newHTTPClient(cfg)
}

// Normalize truncates a client-supplied query vector to dim and L2-renormalizes
// it, so a vector embedded in the browser is safe to cosine-compare against the
// stored embeddings even if the client skipped normalization. Returns nil for an
// empty input.
func Normalize(v []float32, dim int) Vector {
	if len(v) == 0 {
		return nil
	}
	return truncateNormalize(v, dim)
}

// truncateNormalize truncates a (possibly larger native) embedding to dim, then
// L2-renormalizes. Renormalization after Matryoshka truncation is mandatory for
// cosine correctness — the truncated prefix is not unit-length on its own.
func truncateNormalize(v []float32, dim int) Vector {
	if dim > 0 && len(v) > dim {
		v = v[:dim]
	}
	var sumSquares float64
	for _, x := range v {
		sumSquares += float64(x) * float64(x)
	}
	out := make(Vector, len(v))
	if sumSquares == 0 {
		copy(out, v)
		return out
	}
	norm := float32(math.Sqrt(sumSquares))
	for i, x := range v {
		out[i] = x / norm
	}
	return out
}

// ── No-op ─────────────────────────────────────────────────────────────────────

type noopEmbedder struct{}

func (noopEmbedder) EmbedQuery(context.Context, string) (Vector, error) {
	return nil, ErrUnavailable
}

func (noopEmbedder) EmbedDocuments(_ context.Context, texts []string) ([]Vector, error) {
	return nil, ErrUnavailable
}

func (noopEmbedder) Model() string  { return "" }
func (noopEmbedder) Dimension() int { return DefaultDimension }
func (noopEmbedder) Available() bool { return false }

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
