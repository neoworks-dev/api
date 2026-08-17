package database

import (
	"strings"
	"testing"

	gql_model "github.com/neoworks/auth/gql/model"
	"github.com/neoworks/auth/publicerr"
)

// compileFile runs the file filter engine against a fresh compiler with one FTS
// column declared, exercising the shared operator logic the same way the stores
// do. Files are the vehicle because they are the last server-filtered entity —
// contacts, calendar and memories are E2EE envelopes the server cannot read.
func compileFile(f *gql_model.FileFilter) (string, error) {
	c := newFilterCompiler()
	c.ftsColumns = map[string]bool{"filename": true}
	expr := fileFilterEngine.compile(c, f)
	return expr, c.err
}

func TestFilterCompilerSearchRequiresFTSIndex(t *testing.T) {
	// mime_type has no FULLTEXT index → search must be rejected publicly.
	_, err := compileFile(&gql_model.FileFilter{
		MimeType: &gql_model.StringFilter{Search: strptr("image")},
	})
	msg, ok := publicerr.Message(err)
	if !ok {
		t.Fatalf("want public error, got %v", err)
	}
	if !strings.Contains(msg, "FULLTEXT") || !strings.Contains(msg, "mime_type") {
		t.Fatalf("message should name the field and FULLTEXT: %q", msg)
	}
}

func TestFilterCompilerSearchOnIndexedColumnCompiles(t *testing.T) {
	expr, err := compileFile(&gql_model.FileFilter{
		Filename: &gql_model.StringFilter{Search: strptr("invoice")},
	})
	if err != nil {
		t.Fatalf("search on filename should compile: %v", err)
	}
	if !strings.Contains(expr, "@@") {
		t.Fatalf("expected an @@ match expression, got %q", expr)
	}
}

func TestFilterCompilerInvalidDurationIsPublic(t *testing.T) {
	_, err := compileFile(&gql_model.FileFilter{
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
	root := &gql_model.FileFilter{}
	node := root
	for i := 0; i <= maxFilterDepth+1; i++ {
		child := &gql_model.FileFilter{}
		node.Not = child
		node = child
	}
	node.Size = &gql_model.IntFilter{Eq: intptr(1)}

	_, err := compileFile(root)
	if _, ok := publicerr.Message(err); !ok {
		t.Fatalf("want public depth-cap error, got %v", err)
	}
}

func TestFilterCompilerValidFilterHasNoError(t *testing.T) {
	expr, err := compileFile(&gql_model.FileFilter{
		Size:      &gql_model.IntFilter{Eq: intptr(5)},
		CreatedAt: &gql_model.DateFilter{WithinLast: strptr("30d")},
	})
	if err != nil {
		t.Fatalf("valid filter should not error: %v", err)
	}
	if expr == "" {
		t.Fatal("expected a non-empty WHERE expression")
	}
}
