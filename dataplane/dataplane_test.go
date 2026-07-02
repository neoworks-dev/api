package dataplane

import (
	"testing"

	"github.com/graphql-go/graphql"
)

func TestGraphQLTypeMapping(t *testing.T) {
	cases := map[string]string{
		"string":   "String",
		"uuid":     "String",
		"datetime": "String",
		"duration": "String",
		"decimal":  "String", // String to preserve precision
		"int":      "Int",
		"float":    "Float",
		"bool":     "Boolean",
		"object":   "JSON",
		"any":      "JSON",
	}
	for in, want := range cases {
		if got := graphQLType(in).Name(); got != want {
			t.Errorf("graphQLType(%q) = %q, want %q", in, got, want)
		}
	}

	// option<T> unwraps to the inner (nullable) type.
	if got := graphQLType("option<int>").Name(); got != "Int" {
		t.Errorf("option<int> = %q, want Int", got)
	}
	// array<T>/set<T> become lists of the element type.
	list, ok := graphQLType("array<float>").(*graphql.List)
	if !ok {
		t.Fatalf("array<float> is not a List")
	}
	if list.OfType.Name() != "Float" {
		t.Errorf("array<float> element = %q, want Float", list.OfType.Name())
	}
	if _, ok := graphQLType("set<string>").(*graphql.List); !ok {
		t.Errorf("set<string> is not a List")
	}
}

func TestParseRegistrySchemaSkipsSubjectUser(t *testing.T) {
	validated := map[string]any{
		"name": "object",
		"fields": []any{
			map[string]any{"name": "type", "type": "string"},
			map[string]any{"name": "x", "type": "option<float>"},
			map[string]any{"name": "subject_user_id", "type": "string"}, // reserved, must be skipped
		},
	}
	spec, err := parseRegistrySchema("data", false, validated)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if spec.name != "object" {
		t.Errorf("name = %q", spec.name)
	}
	for _, f := range spec.fields {
		if f.name == "subject_user_id" {
			t.Fatalf("subject_user_id leaked into spec")
		}
	}
	if len(spec.fields) != 2 {
		t.Errorf("got %d fields, want 2", len(spec.fields))
	}
}

func TestParseRegistrySchemaRejectsBadIdentifiers(t *testing.T) {
	bad := map[string]any{"name": "ok", "fields": []any{
		map[string]any{"name": "bad name", "type": "string"},
	}}
	if _, err := parseRegistrySchema("data", false, bad); err == nil {
		t.Fatal("expected error for invalid field name")
	}
	if _, err := parseRegistrySchema("data", false, map[string]any{"name": "1bad"}); err == nil {
		t.Fatal("expected error for invalid table name")
	}
}

func dataSpec() tableSpec {
	return tableSpec{name: "object", versioned: false, fields: []fieldSpec{
		{name: "type", typ: "string"},
		{name: "x", typ: "option<float>"},
		{name: "payload", typ: "object"},
	}}
}

func TestBuildSchemaHidesInternalFields(t *testing.T) {
	schema, err := buildSchema(nil, []tableSpec{dataSpec()})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	obj, ok := schema.Type("object").(*graphql.Object)
	if !ok {
		t.Fatal("object type missing")
	}
	fields := obj.Fields()
	if _, ok := fields["id"]; !ok {
		t.Error("object type missing id")
	}
	if _, ok := fields["type"]; !ok {
		t.Error("object type missing declared field")
	}
	if _, ok := fields["subject_user_id"]; ok {
		t.Error("subject_user_id must not be exposed")
	}
	if _, ok := fields["version"]; ok {
		t.Error("version must not be exposed")
	}

	createInput, ok := schema.Type("objectCreateInput").(*graphql.InputObject)
	if !ok {
		t.Fatal("objectCreateInput missing")
	}
	if _, ok := createInput.Fields()["subject_user_id"]; ok {
		t.Error("subject_user_id must not be writable")
	}

	q := schema.QueryType().Fields()
	if _, ok := q["object"]; !ok {
		t.Error("missing get query")
	}
	if _, ok := q["objects"]; !ok {
		t.Error("missing list query")
	}
	m := schema.MutationType().Fields()
	for _, name := range []string{"createObject", "updateObject", "deleteObject"} {
		if _, ok := m[name]; !ok {
			t.Errorf("missing mutation %q", name)
		}
	}
}

func TestBuildSchemaVersioned(t *testing.T) {
	spec := dataSpec()
	spec.versioned = true
	schema, err := buildSchema(nil, []tableSpec{spec})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if _, ok := schema.QueryType().Fields()["objectHistory"]; !ok {
		t.Error("versioned table missing history query")
	}

	upd := schema.MutationType().Fields()["updateObject"]
	hasParents := false
	for _, a := range upd.Args {
		if a.Name() == "parentVersionIds" {
			hasParents = true
		}
	}
	if !hasParents {
		t.Error("versioned update missing parentVersionIds arg")
	}

	// created_at / updated_at are exposed for versioned tables.
	obj := schema.Type("object").(*graphql.Object)
	if _, ok := obj.Fields()["created_at"]; !ok {
		t.Error("versioned object missing created_at")
	}
}

func TestBuildSchemaCollision(t *testing.T) {
	// A table named "object" and another named "objectCreateInput" would collide
	// on generated type names.
	specs := []tableSpec{
		{name: "object", fields: []fieldSpec{{name: "a", typ: "string"}}},
		{name: "objectCreateInput", fields: []fieldSpec{{name: "b", typ: "string"}}},
	}
	if _, err := buildSchema(nil, specs); err == nil {
		t.Fatal("expected collision error")
	}
}
