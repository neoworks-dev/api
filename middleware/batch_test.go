package middleware

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// echoHandler replies with a {data:{body}} envelope mirroring the request body,
// so tests can assert each operation was executed independently and in order.
func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":` + string(body) + `}`))
	})
}

func post(t *testing.T, handler http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestBatchPassesThroughSingleObject(t *testing.T) {
	recorder := post(t, Batch(echoHandler()), `{"query":"{ a }"}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	want := `{"data":{"query":"{ a }"}}`
	if got := recorder.Body.String(); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

func TestBatchSplitsArrayInOrder(t *testing.T) {
	recorder := post(t, Batch(echoHandler()), `[{"query":"1"},{"query":"2"},{"query":"3"}]`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	var results []json.RawMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &results); err != nil {
		t.Fatalf("response is not a JSON array: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("len(results) = %d, want 3", len(results))
	}
	want := []string{`{"data":{"query":"1"}}`, `{"data":{"query":"2"}}`, `{"data":{"query":"3"}}`}
	for index, result := range results {
		if string(result) != want[index] {
			t.Errorf("result[%d] = %s, want %s", index, result, want[index])
		}
	}
}

func TestBatchRejectsEmptyArray(t *testing.T) {
	recorder := post(t, Batch(echoHandler()), `[]`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
}

func TestBatchEnforcesMaxSize(t *testing.T) {
	recorder := post(t, BatchWithLimit(echoHandler(), 2), `[{"query":"1"},{"query":"2"},{"query":"3"}]`)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", recorder.Code)
	}
}

func TestBatchFailsWholeBatchOnTransportError(t *testing.T) {
	// Inner handler rejects the second operation with a 401.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "deny") {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"data":{}}`))
	})

	recorder := post(t, Batch(inner), `[{"query":"ok"},{"query":"deny"}]`)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
}

func TestBatchIgnoresLeadingWhitespace(t *testing.T) {
	recorder := post(t, Batch(echoHandler()), "  \n [{\"query\":\"1\"}]")
	var results []json.RawMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &results); err != nil {
		t.Fatalf("expected JSON array, got %s", recorder.Body.String())
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
}

func TestBatchLeavesGetRequestsAlone(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	request := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	Batch(inner).ServeHTTP(httptest.NewRecorder(), request)
	if !called {
		t.Fatal("GET request was not forwarded to the inner handler")
	}
}
