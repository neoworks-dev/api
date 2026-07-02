package embeddings

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Nomic embed task prefixes for asymmetric retrieval. nomic-embed-text-v1.5
// requires these on every input; the matching nomic-embed-vision-v1.5 image
// embeddings live in the same space, so a "search_query:"-prefixed text query
// retrieves both text and images.
const (
	queryPrefix    = "search_query: "
	documentPrefix = "search_document: "
)

type httpClient struct {
	http      *http.Client
	url       string // base, e.g. http://localhost:11434/v1
	model     string
	apiKey    string
	dimension int
	batchSize int
}

func newHTTPClient(cfg Config) *httpClient {
	return &httpClient{
		http:      &http.Client{Timeout: cfg.Timeout},
		url:       strings.TrimRight(cfg.URL, "/"),
		model:     cfg.Model,
		apiKey:    cfg.APIKey,
		dimension: cfg.Dimension,
		batchSize: cfg.BatchSize,
	}
}

func (c *httpClient) Model() string   { return c.model }
func (c *httpClient) Dimension() int  { return c.dimension }
func (c *httpClient) Available() bool { return true }

func (c *httpClient) EmbedQuery(ctx context.Context, text string) (Vector, error) {
	vectors, err := c.embed(ctx, []string{queryPrefix + text})
	if err != nil {
		return nil, err
	}
	if len(vectors) == 0 {
		return nil, fmt.Errorf("embeddings: empty response for query")
	}
	return vectors[0], nil
}

func (c *httpClient) EmbedDocuments(ctx context.Context, texts []string) ([]Vector, error) {
	if len(texts) == 0 {
		return nil, nil
	}
	out := make([]Vector, 0, len(texts))
	for start := 0; start < len(texts); start += c.batchSize {
		end := start + c.batchSize
		if end > len(texts) {
			end = len(texts)
		}
		batch := make([]string, end-start)
		for i, text := range texts[start:end] {
			batch[i] = documentPrefix + text
		}
		vectors, err := c.embed(ctx, batch)
		if err != nil {
			return nil, err
		}
		out = append(out, vectors...)
	}
	return out, nil
}

// ── OpenAI-compatible /v1/embeddings ──────────────────────────────────────────

type embeddingRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

type embeddingResponse struct {
	Data []struct {
		Index     int       `json:"index"`
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
}

func (c *httpClient) embed(ctx context.Context, inputs []string) ([]Vector, error) {
	body, err := json.Marshal(embeddingRequest{Model: c.model, Input: inputs})
	if err != nil {
		return nil, fmt.Errorf("embeddings: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("embeddings: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("embeddings: post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("embeddings: server returned %s", resp.Status)
	}

	var parsed embeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("embeddings: decode: %w", err)
	}
	if len(parsed.Data) != len(inputs) {
		return nil, fmt.Errorf("embeddings: expected %d vectors, got %d", len(inputs), len(parsed.Data))
	}

	// The OpenAI shape carries an index per row; sort to guarantee input order.
	sort.Slice(parsed.Data, func(i, j int) bool { return parsed.Data[i].Index < parsed.Data[j].Index })

	out := make([]Vector, len(parsed.Data))
	for i, d := range parsed.Data {
		out[i] = truncateNormalize(d.Embedding, c.dimension)
	}
	return out, nil
}

// compile-time guard.
var _ Embedder = (*httpClient)(nil)
