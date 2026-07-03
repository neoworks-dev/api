package gql

import (
	"testing"

	gql_model "github.com/neoworks/auth/gql/model"
)

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }

// DDL generation moved to the OpenSchema compiler (the neoworks-ddl emitter). The
// tests below cover the Go validation + registry classification that remains.

func TestRewriteFulltextRejectsNonStringField(t *testing.T) {
	input := &gql_model.DatabaseSchemaInput{
		Tables: []*gql_model.TableDefInput{
			{
				Name:   "schema",
				Fields: []*gql_model.FieldDefInput{{Name: "downloads", Type: "int"}},
				Indexes: []*gql_model.IndexDefInput{
					{Name: "idx_dl_fts", Fields: []string{"downloads"}, Fulltext: boolPtr(true)},
				},
			},
		},
	}
	if _, err := rewriteSchemaInput(input); err == nil {
		t.Error("fulltext index on a non-string field should be rejected")
	}
}

func TestRewriteClassifiesDataTable(t *testing.T) {
	input := &gql_model.DatabaseSchemaInput{
		Tables: []*gql_model.TableDefInput{
			{Name: "note", Fields: []*gql_model.FieldDefInput{{Name: "body", Type: "string"}}},
		},
	}
	tables, err := rewriteSchemaInput(input)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if len(tables) != 1 {
		t.Fatalf("want 1 table, got %d", len(tables))
	}
	if !tables[0].hasSubjectUser {
		t.Error("data table should be flagged hasSubjectUser")
	}
	if tables[0].hasInternal {
		t.Error("data table must not be flagged internal")
	}
}

func TestRewriteClassifiesHistoryTable(t *testing.T) {
	input := &gql_model.DatabaseSchemaInput{
		Tables: []*gql_model.TableDefInput{
			{Name: "doc", History: boolPtr(true), Fields: []*gql_model.FieldDefInput{{Name: "title", Type: "string"}}},
		},
	}
	tables, err := rewriteSchemaInput(input)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if !tables[0].versioned {
		t.Error("table should be flagged versioned")
	}
}

func TestRewriteRelationTableRequiresSubjectPath(t *testing.T) {
	input := &gql_model.DatabaseSchemaInput{
		Tables: []*gql_model.TableDefInput{
			{Name: "likes", Kind: strPtr("relation")},
		},
	}
	if _, err := rewriteSchemaInput(input); err == nil {
		t.Fatal("relation table without subjectPath should fail")
	}

	input.Tables[0].SubjectPath = strPtr("in.subject_user_id")
	tables, err := rewriteSchemaInput(input)
	if err != nil {
		t.Fatalf("rewrite with subjectPath: %v", err)
	}
	if tables[0].hasSubjectUser {
		t.Error("relation table must not be flagged hasSubjectUser")
	}
	if tables[0].subjectPath != "in.subject_user_id" {
		t.Errorf("subjectPath = %q, want in.subject_user_id", tables[0].subjectPath)
	}
}

func TestRewriteClassifiesInternalTable(t *testing.T) {
	input := &gql_model.DatabaseSchemaInput{
		Tables: []*gql_model.TableDefInput{
			{
				Name:       "message",
				Kind:       strPtr("internal"),
				Visibility: strPtr("public"),
				Fields:     []*gql_model.FieldDefInput{{Name: "body", Type: "string"}},
			},
		},
	}
	tables, err := rewriteSchemaInput(input)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if tables[0].hasSubjectUser {
		t.Error("internal table must not be flagged hasSubjectUser")
	}
	if !tables[0].hasInternal {
		t.Error("internal table should be flagged internal")
	}
}

func TestRewriteInternalTableRejectsHistory(t *testing.T) {
	input := &gql_model.DatabaseSchemaInput{
		Tables: []*gql_model.TableDefInput{
			{Name: "message", Kind: strPtr("internal"), History: boolPtr(true)},
		},
	}
	if _, err := rewriteSchemaInput(input); err == nil {
		t.Fatal("internal table requesting history should fail")
	}
}

func TestRewriteRejectsReservedOrganizationField(t *testing.T) {
	input := &gql_model.DatabaseSchemaInput{
		Tables: []*gql_model.TableDefInput{
			{Name: "message", Kind: strPtr("internal"), Fields: []*gql_model.FieldDefInput{{Name: "organization_id", Type: "string"}}},
		},
	}
	if _, err := rewriteSchemaInput(input); err == nil {
		t.Fatal("submitting reserved organization_id should fail")
	}
}

func TestRewriteRejectsInvalidVisibility(t *testing.T) {
	input := &gql_model.DatabaseSchemaInput{
		Tables: []*gql_model.TableDefInput{
			{Name: "message", Kind: strPtr("internal"), Visibility: strPtr("sometimes")},
		},
	}
	if _, err := rewriteSchemaInput(input); err == nil {
		t.Fatal("invalid visibility should fail")
	}
}

func TestRewriteRejectsReservedField(t *testing.T) {
	input := &gql_model.DatabaseSchemaInput{
		Tables: []*gql_model.TableDefInput{
			{Name: "note", Fields: []*gql_model.FieldDefInput{{Name: "subject_user_id", Type: "string"}}},
		},
	}
	if _, err := rewriteSchemaInput(input); err == nil {
		t.Fatal("submitting reserved subject_user_id should fail")
	}
}

func TestParseScope(t *testing.T) {
	cases := []struct {
		raw     string
		wantErr bool
		org     string
		entity  string
		action  string
	}{
		{"contacts:read", false, "", "contacts", "read"},
		{"org_123:documents:write", false, "org_123", "documents", "write"},
		{"contacts", true, "", "", ""},
		{"a:b:c:d", true, "", "", ""},
		{"contacts:delete", true, "", "", ""},
		{":read", true, "", "", ""},
	}
	for _, c := range cases {
		got, err := parseScope(c.raw)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseScope(%q): expected error", c.raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseScope(%q): unexpected error %v", c.raw, err)
			continue
		}
		if got.OrgSlug != c.org || got.Entity != c.entity || got.Action != c.action {
			t.Errorf("parseScope(%q) = %+v, want org=%q entity=%q action=%q", c.raw, got, c.org, c.entity, c.action)
		}
	}
}
