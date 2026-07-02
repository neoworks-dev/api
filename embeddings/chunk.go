package embeddings

import "strings"

// Chunk is a slice of source text plus its character offsets in the original.
type Chunk struct {
	Content string
	Start   int
	End     int
}

// Chunker splits source text into embeddable pieces.
type Chunker interface {
	Chunk(text string) []Chunk
}

// Defaults for the character-window chunker. ~4 chars per token, so a 2048-char
// window ≈ 512 tokens with ~256-char (~64-token) overlap — a retrieval-friendly
// size. Character approximation avoids a tokenizer dependency; revisit if recall
// suffers on token-dense text.
const (
	DefaultChunkSize    = 2048
	DefaultChunkOverlap = 256
)

// CharChunker splits on a sliding character window, preferring to break on
// paragraph or sentence boundaries near the window edge so chunks stay coherent.
type CharChunker struct {
	Size    int
	Overlap int
}

func NewCharChunker() CharChunker {
	return CharChunker{Size: DefaultChunkSize, Overlap: DefaultChunkOverlap}
}

func (c CharChunker) Chunk(text string) []Chunk {
	size := c.Size
	if size <= 0 {
		size = DefaultChunkSize
	}
	overlap := c.Overlap
	if overlap < 0 || overlap >= size {
		overlap = DefaultChunkOverlap
	}

	runes := []rune(text)
	if len(strings.TrimSpace(text)) == 0 {
		return nil
	}
	if len(runes) <= size {
		return []Chunk{{Content: text, Start: 0, End: len(runes)}}
	}

	var chunks []Chunk
	start := 0
	for start < len(runes) {
		end := start + size
		if end >= len(runes) {
			chunks = append(chunks, Chunk{Content: string(runes[start:]), Start: start, End: len(runes)})
			break
		}
		// Pull the cut back to the nearest boundary within the last 25% of the
		// window, so we don't split mid-sentence.
		end = boundaryBefore(runes, start, end, size/4)
		chunks = append(chunks, Chunk{Content: string(runes[start:end]), Start: start, End: end})

		next := end - overlap
		if next <= start {
			next = end // guard against no forward progress
		}
		start = next
	}
	return chunks
}

// boundaryBefore returns the best break offset in (end-window, end], preferring a
// paragraph break, then a sentence end, then whitespace; falls back to end.
func boundaryBefore(runes []rune, start, end, window int) int {
	low := end - window
	if low <= start {
		low = start + 1
	}
	paragraph, sentence, space := -1, -1, -1
	for i := low; i < end; i++ {
		switch runes[i] {
		case '\n':
			if i+1 < len(runes) && runes[i+1] == '\n' {
				paragraph = i + 1
			}
		case '.', '!', '?':
			if i+1 < len(runes) && (runes[i+1] == ' ' || runes[i+1] == '\n') {
				sentence = i + 1
			}
		case ' ', '\t':
			space = i
		}
	}
	switch {
	case paragraph != -1:
		return paragraph
	case sentence != -1:
		return sentence
	case space != -1:
		return space
	default:
		return end
	}
}
