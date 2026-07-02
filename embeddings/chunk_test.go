package embeddings

import (
	"math"
	"strings"
	"testing"
)

func TestCharChunkerShortTextIsSingleChunk(t *testing.T) {
	text := "ella's email is ella@example.com"
	chunks := NewCharChunker().Chunk(text)
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}
	if chunks[0].Content != text {
		t.Errorf("content mismatch: %q", chunks[0].Content)
	}
	if chunks[0].Start != 0 || chunks[0].End != len([]rune(text)) {
		t.Errorf("offsets wrong: %d-%d", chunks[0].Start, chunks[0].End)
	}
}

func TestCharChunkerEmptyIsNoChunks(t *testing.T) {
	if got := NewCharChunker().Chunk("   \n  "); got != nil {
		t.Errorf("expected nil for blank text, got %#v", got)
	}
}

func TestCharChunkerSplitsWithOverlap(t *testing.T) {
	c := CharChunker{Size: 100, Overlap: 20}
	// 500 sentences, well over the window.
	text := strings.Repeat("This is a sentence. ", 50)
	chunks := c.Chunk(text)
	if len(chunks) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(chunks))
	}
	// Each chunk (except possibly the last) must respect the window size.
	for i, ch := range chunks {
		if ch.End-ch.Start > c.Size {
			t.Errorf("chunk %d exceeds window: %d runes", i, ch.End-ch.Start)
		}
	}
	// Consecutive chunks must overlap (next starts before previous ends).
	for i := 1; i < len(chunks); i++ {
		if chunks[i].Start >= chunks[i-1].End {
			t.Errorf("chunk %d does not overlap previous (%d >= %d)", i, chunks[i].Start, chunks[i-1].End)
		}
	}
	// Offsets must be monotonically advancing (no infinite loop / stall).
	for i := 1; i < len(chunks); i++ {
		if chunks[i].Start <= chunks[i-1].Start {
			t.Errorf("chunk %d start did not advance", i)
		}
	}
}

func TestTruncateNormalizeProducesUnitLength(t *testing.T) {
	raw := make([]float32, 2048)
	for i := range raw {
		raw[i] = float32(i%7) + 1
	}
	v := truncateNormalize(raw, DefaultDimension)
	if len(v) != DefaultDimension {
		t.Fatalf("expected len %d, got %d", DefaultDimension, len(v))
	}
	var sumSquares float64
	for _, x := range v {
		sumSquares += float64(x) * float64(x)
	}
	if math.Abs(math.Sqrt(sumSquares)-1.0) > 1e-5 {
		t.Errorf("vector not unit length: norm=%f", math.Sqrt(sumSquares))
	}
}

func TestTruncateNormalizeZeroVector(t *testing.T) {
	v := truncateNormalize(make([]float32, 1024), DefaultDimension)
	if len(v) != DefaultDimension {
		t.Fatalf("expected len %d, got %d", DefaultDimension, len(v))
	}
	for _, x := range v {
		if x != 0 {
			t.Fatalf("expected zero vector to stay zero")
		}
	}
}
