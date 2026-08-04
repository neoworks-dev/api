package database

import (
	"strings"
	"testing"

	gql_model "github.com/neoworks/auth/gql/model"
	"github.com/neoworks/auth/publicerr"
)

// compileEvent runs the event filter engine against a fresh compiler with one
// FTS column declared, exercising the shared operator logic the same way the
// stores do. (Contacts moved to E2EE envelopes and no longer server-filter.)
func compileEvent(f *gql_model.EventFilter) (string, error) {
	c := newFilterCompiler()
	c.ftsColumns = map[string]bool{"title": true}
	expr := eventFilterEngine.compile(c, f)
	return expr, c.err
}

func TestFilterCompilerSearchRequiresFTSIndex(t *testing.T) {
	// description has no FULLTEXT index → search must be rejected publicly.
	_, err := compileEvent(&gql_model.EventFilter{
		Description: &gql_model.StringFilter{Search: strptr("standup")},
	})
	msg, ok := publicerr.Message(err)
	if !ok {
		t.Fatalf("want public error, got %v", err)
	}
	if !strings.Contains(msg, "FULLTEXT") || !strings.Contains(msg, "description") {
		t.Fatalf("message should name the field and FULLTEXT: %q", msg)
	}
}

func TestFilterCompilerSearchOnIndexedColumnCompiles(t *testing.T) {
	expr, err := compileEvent(&gql_model.EventFilter{
		Title: &gql_model.StringFilter{Search: strptr("standup")},
	})
	if err != nil {
		t.Fatalf("search on title should compile: %v", err)
	}
	if !strings.Contains(expr, "@@") {
		t.Fatalf("expected an @@ match expression, got %q", expr)
	}
}

func TestFilterCompilerInvalidDurationIsPublic(t *testing.T) {
	_, err := compileEvent(&gql_model.EventFilter{
		CreatedAt: &gql_model.DateFilter{WithinLast: strptr("30x")},
	})
	msg, ok := publicerr.Message(err)
	if !ok {
		t.Fatalf("want public error, got %v", err)
	}
	if !strings.Contains(msg, "withinLast") {
		t.Fatalf("message should mention withinLast: %q", msg)
	}
}

func TestFilterCompilerDepthCapIsPublic(t *testing.T) {
	// Nest Not deeper than maxFilterDepth.
	root := &gql_model.EventFilter{}
	node := root
	for i := 0; i <= maxFilterDepth+1; i++ {
		child := &gql_model.EventFilter{}
		node.Not = child
		node = child
	}
	node.Priority = &gql_model.IntFilter{Eq: intptr(1)}

	_, err := compileEvent(root)
	if _, ok := publicerr.Message(err); !ok {
		t.Fatalf("want public depth-cap error, got %v", err)
	}
}

func TestFilterCompilerValidFilterHasNoError(t *testing.T) {
	expr, err := compileEvent(&gql_model.EventFilter{
		Priority:  &gql_model.IntFilter{Eq: intptr(5)},
		CreatedAt: &gql_model.DateFilter{WithinLast: strptr("30d")},
	})
	if err != nil {
		t.Fatalf("valid filter should not error: %v", err)
	}
	if expr == "" {
		t.Fatal("expected a non-empty WHERE expression")
	}
}
