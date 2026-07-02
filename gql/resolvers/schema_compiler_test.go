package gql

import (
	"context"
	"net/http"
	"testing"
)

// Exercises the Go → schema-compiler sidecar → DatabaseSchemaInput decode path,
// including that @neoworks.* decorators round-trip into the model fields the Go
// rewrite reads. Skips when the sidecar isn't running.
func TestCompileSchemaSourceIntegration(t *testing.T) {
	url := schemaCompilerURL()
	if resp, err := http.Get(url + "/health"); err != nil {
		t.Skipf("schema-compiler not reachable at %s: %v", url, err)
	} else {
		_ = resp.Body.Close()
	}

	source := `namespace t
@neoworks.kind("org") @neoworks.visibility("public")
@neoworks.unique("scope", "name")
model Schema {
  1 scope: string
  @neoworks.fulltext 2 name: string
  3 downloads: i64
}`

	schema, err := compileSchemaSource(context.Background(), source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if schema == nil || len(schema.Tables) != 1 {
		t.Fatalf("want 1 table, got %+v", schema)
	}

	table := schema.Tables[0]
	if table.Name != "schema" {
		t.Errorf("name = %q, want schema", table.Name)
	}
	if table.Kind == nil || *table.Kind != "org" {
		t.Errorf("kind = %v, want org", table.Kind)
	}
	if table.Visibility == nil || *table.Visibility != "public" {
		t.Errorf("visibility = %v, want public", table.Visibility)
	}

	var fulltext, composite bool
	for _, idx := range table.Indexes {
		if idx.Fulltext != nil && *idx.Fulltext {
			fulltext = true
		}
		if idx.Unique != nil && *idx.Unique && len(idx.Fields) == 2 {
			composite = true
		}
	}
	if !fulltext {
		t.Error("expected a fulltext index from @neoworks.fulltext")
	}
	if !composite {
		t.Error("expected a composite unique index from @neoworks.unique")
	}

	// Empty source compiles to no schema (a database may be created without one).
	empty, err := compileSchemaSource(context.Background(), "   ")
	if err != nil || empty != nil {
		t.Errorf("empty source: schema=%v err=%v", empty, err)
	}
}

func TestSchemaCompilerURLDefault(t *testing.T) {
	t.Setenv("SCHEMA_COMPILER_URL", "")
	if got := schemaCompilerURL(); got != "http://127.0.0.1:8086" {
		t.Errorf("default url = %q", got)
	}
	t.Setenv("SCHEMA_COMPILER_URL", "http://example:9000")
	if got := schemaCompilerURL(); got != "http://example:9000" {
		t.Errorf("override url = %q", got)
	}
}
