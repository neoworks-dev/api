package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
)

// DefaultMaxBatchSize bounds how many operations a single batched request may
// carry, protecting the server from an unbounded fan-out in one HTTP call.
const DefaultMaxBatchSize = 25

// Batch wraps a GraphQL handler so it also accepts query batching: a request
// whose JSON body is an array of operations is split, each operation is replayed
// through next independently, and the per-operation responses are returned as a
// JSON array in the same order. A non-array body passes through untouched, so
// single-operation requests behave exactly as before.
//
// This matches the genql client's batching wire format ([{query,variables}, ...]
// in, [{data,errors}, ...] out) without requiring the underlying handler to know
// anything about batching.
func Batch(next http.Handler) http.Handler {
	return BatchWithLimit(next, DefaultMaxBatchSize)
}

// BatchWithLimit is Batch with an explicit maximum batch size.
func BatchWithLimit(next http.Handler, maxBatchSize int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}

		if !isJSONArray(body) {
			// Not a batch — restore the body and forward unchanged.
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
			return
		}

		var operations []json.RawMessage
		if err := json.Unmarshal(body, &operations); err != nil {
			http.Error(w, `{"error":"invalid batch body"}`, http.StatusBadRequest)
			return
		}
		if len(operations) == 0 {
			http.Error(w, `{"error":"empty batch"}`, http.StatusBadRequest)
			return
		}
		if len(operations) > maxBatchSize {
			http.Error(w, `{"error":"batch too large"}`, http.StatusRequestEntityTooLarge)
			return
		}

		results := make([]json.RawMessage, len(operations))
		for index, operation := range operations {
			status, responseBody := replayOne(next, r, operation)
			// A transport-level failure on any operation fails the whole batch:
			// the client shares one token, so partial auth/transport errors are
			// not individually recoverable. GraphQL-level errors come back as 200.
			if status != http.StatusOK {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = w.Write(responseBody)
				return
			}
			results[index] = responseBody
		}

		out, err := json.Marshal(results)
		if err != nil {
			http.Error(w, `{"error":"batch encoding failed"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	})
}

// replayOne runs a single operation through next on a fresh recorder, carrying
// the original request's context so auth claims and route params survive.
func replayOne(next http.Handler, original *http.Request, operation json.RawMessage) (int, []byte) {
	subRequest := original.Clone(original.Context())
	subRequest.Body = io.NopCloser(bytes.NewReader(operation))
	subRequest.ContentLength = int64(len(operation))
	subRequest.GetBody = nil
	subRequest.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	next.ServeHTTP(recorder, subRequest)
	return recorder.Code, recorder.Body.Bytes()
}

// isJSONArray reports whether the first non-whitespace byte is '[', i.e. the
// body is a JSON array rather than a single object.
func isJSONArray(body []byte) bool {
	for _, b := range body {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case '[':
			return true
		default:
			return false
		}
	}
	return false
}
