package dataplane

import (
	"context"
	"strings"
	"testing"
)

func searchableSpec() tableSpec {
	return tableSpec{name: "schema", internal: true, visibility: visibilityPublic, fields: []fieldSpec{
		{name: "name", typ: "string"},
		{name: "description", typ: "string"},
	}, searchFields: []string{"name", "description"}}
}

func TestParseRegistrySchemaCollectsFulltextSearchFields(t *testing.T) {
	validated := map[string]any{
		"name": "schema",
		"fields": []any{
			map[string]any{"name": "name", "type": "string"},
			map[string]any{"name": "description", "type": "string"},
			map[string]any{"name": "downloads_total", "type": "int"},
		},
		"indexes": []any{
			map[string]any{"name": "idx_scope_name", "fields": []any{"scope", "name"}, "unique": true},
			map[string]any{"name": "idx_name_fts", "fields": []any{"name"}, "fulltext": true},
			map[string]any{"name": "idx_desc_fts", "fields": []any{"description"}, "fulltext": true},
		},
	}
	spec, err := parseRegistrySchema("shared", false, validated)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"name", "description"}
	if strings.Join(spec.searchFields, ",") != strings.Join(want, ",") {
		t.Errorf("searchFields = %v, want %v", spec.searchFields, want)
	}
}

func TestBuildSchemaExposesSearchArgWhenIndexed(t *testing.T) {
	schema, err := buildSchema(nil, []tableSpec{searchableSpec()})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	list := schema.QueryType().Fields()["schemas"]
	var hasSearch bool
	for _, a := range list.Args {
		if a.Name() == "search" {
			hasSearch = true
		}
	}
	if !hasSearch {
		t.Error("indexed table list query missing `search` argument")
	}
}

func TestListSearchBuildsBM25Query(t *testing.T) {
	m := &mockQuerier{}
	ctx := withRequest(context.Background(), requestInfo{dbName: "db"})
	args := map[string]any{"search": "commerce"}
	if _, err := listResolver(m, searchableSpec())(resolveParams(ctx, args)); err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, want := range []string{"`name` @0@ $search", "`description` @1@ $search", "search::score(0) + search::score(1)"} {
		if !strings.Contains(m.lastQuery, want) {
			t.Errorf("search query missing %q:\n%s", want, m.lastQuery)
		}
	}
	if m.lastParams["search"] != "commerce" {
		t.Errorf("search term not bound: %v", m.lastParams["search"])
	}
}

func TestListSearchIgnoredWithoutIndex(t *testing.T) {
	// A spec with no searchFields must not interpolate any @@ match even if a
	// caller smuggles a search arg.
	spec := tableSpec{name: "plain", internal: true, visibility: visibilityPublic, fields: []fieldSpec{{name: "body", typ: "string"}}}
	m := &mockQuerier{}
	ctx := withRequest(context.Background(), requestInfo{dbName: "db"})
	if _, err := listResolver(m, spec)(resolveParams(ctx, map[string]any{"search": "x"})); err != nil {
		t.Fatalf("list: %v", err)
	}
	if strings.Contains(m.lastQuery, "@0@") || strings.Contains(m.lastQuery, "search::score") {
		t.Errorf("unindexed table must not build a search clause: %s", m.lastQuery)
	}
}
