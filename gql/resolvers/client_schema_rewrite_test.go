package gql

import (
	"strings"
	"testing"

	gql_model "github.com/neoworks/auth/gql/model"
)

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }

func ddlContains(ddl []string, substr string) bool {
	for _, stmt := range ddl {
		if strings.Contains(stmt, substr) {
			return true
		}
	}
	return false
}

func TestRewriteFulltextIndexEmitsAnalyzerAndBM25Index(t *testing.T) {
	input := &gql_model.DatabaseSchemaInput{
		Tables: []*gql_model.TableDefInput{
			{
				Name:       "schema",
				Schemafull: boolPtr(true),
				Kind:       strPtr("internal"),
				Visibility: strPtr("public"),
				Fields: []*gql_model.FieldDefInput{
					{Name: "name", Type: "string"},
					{Name: "description", Type: "string"},
				},
				Indexes: []*gql_model.IndexDefInput{
					{Name: "idx_name_fts", Fields: []string{"name"}, Fulltext: boolPtr(true)},
				},
			},
		},
	}
	tables, err := rewriteSchemaInput(input)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	var all []string
	for _, rt := range tables {
		all = append(all, rt.ddl...)
	}

	// The analyzer must be defined and ordered before the index that references it.
	analyzerStmt := "DEFINE ANALYZER OVERWRITE `text_en` TOKENIZERS blank, class FILTERS lowercase, ascii, snowball(english);"
	indexStmt := "DEFINE INDEX OVERWRITE `idx_name_fts` ON `schema` FIELDS `name` FULLTEXT ANALYZER `text_en` BM25 HIGHLIGHTS;"
	analyzerAt, indexAt := -1, -1
	for i, stmt := range all {
		if stmt == analyzerStmt {
			analyzerAt = i
		}
		if stmt == indexStmt {
			indexAt = i
		}
	}
	if analyzerAt < 0 {
		t.Errorf("missing analyzer DDL; ddl=%v", all)
	}
	if indexAt < 0 {
		t.Errorf("missing fulltext index DDL; ddl=%v", all)
	}
	if analyzerAt >= 0 && indexAt >= 0 && analyzerAt > indexAt {
		t.Errorf("analyzer (%d) must come before index (%d)", analyzerAt, indexAt)
	}
}

func TestRewriteFulltextRejectsNonStringField(t *testing.T) {
	input := &gql_model.DatabaseSchemaInput{
		Tables: []*gql_model.TableDefInput{
			{
				Name:   "schema",
				Kind:   strPtr("shared"),
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

func TestRewriteInjectsSubjectUserIDOnDataTable(t *testing.T) {
	input := &gql_model.DatabaseSchemaInput{
		Tables: []*gql_model.TableDefInput{
			{
				Name:       "note",
				Schemafull: boolPtr(true),
				Fields:     []*gql_model.FieldDefInput{{Name: "body", Type: "string"}},
			},
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
		t.Error("data table should carry subject_user_id")
	}
	if !ddlContains(tables[0].ddl, "DEFINE FIELD OVERWRITE `subject_user_id` ON `note` TYPE string;") {
		t.Errorf("missing subject_user_id field; ddl=%v", tables[0].ddl)
	}
}

func TestRewriteHistoryEmitsVersionedTriple(t *testing.T) {
	input := &gql_model.DatabaseSchemaInput{
		Tables: []*gql_model.TableDefInput{
			{
				Name:    "doc",
				History: boolPtr(true),
				Fields:  []*gql_model.FieldDefInput{{Name: "title", Type: "string"}},
			},
		},
	}
	tables, err := rewriteSchemaInput(input)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	ddl := tables[0].ddl
	if !tables[0].versioned {
		t.Error("table should be versioned")
	}
	checks := []string{
		"DEFINE TABLE IF NOT EXISTS `derived_from` TYPE RELATION;",
		"DEFINE TABLE IF NOT EXISTS `doc`",
		"DEFINE TABLE IF NOT EXISTS `doc_version`",
		"DEFINE FIELD OVERWRITE `doc_id` ON `doc_version`",
		"DEFINE FIELD OVERWRITE `version` ON `doc`",
		"DEFINE FIELD OVERWRITE `title` ON `doc_version` TYPE string READONLY;",
	}
	for _, c := range checks {
		if !ddlContains(ddl, c) {
			t.Errorf("history rewrite missing %q; ddl=%v", c, ddl)
		}
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
		t.Error("relation table must not get subject_user_id injected")
	}
	if ddlContains(tables[0].ddl, "subject_user_id") {
		t.Error("relation table ddl should not contain subject_user_id")
	}
}

func TestRewriteInternalTableHasNoOwnerButKeepsTimestamps(t *testing.T) {
	input := &gql_model.DatabaseSchemaInput{
		Tables: []*gql_model.TableDefInput{
			{
				Name:       "message",
				Schemafull: boolPtr(true),
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
	rt := tables[0]
	if rt.hasSubjectUser {
		t.Error("internal table must not get subject_user_id")
	}
	if !rt.hasInternal {
		t.Error("internal table should be flagged internal")
	}
	// Internal rows have no owner column at all.
	if ddlContains(rt.ddl, "subject_user_id") || ddlContains(rt.ddl, "organization_id") {
		t.Errorf("internal ddl must not contain an owner column; ddl=%v", rt.ddl)
	}
	checks := []string{
		"DEFINE FIELD OVERWRITE `created_at` ON `message` TYPE datetime VALUE $before OR time::now() READONLY;",
		"DEFINE FIELD OVERWRITE `updated_at` ON `message` TYPE datetime VALUE time::now();",
	}
	for _, c := range checks {
		if !ddlContains(rt.ddl, c) {
			t.Errorf("internal rewrite missing %q; ddl=%v", c, rt.ddl)
		}
	}
}

func TestRewriteSharedTableProvisionsGrantTable(t *testing.T) {
	input := &gql_model.DatabaseSchemaInput{
		Tables: []*gql_model.TableDefInput{
			{
				Name:       "doc",
				Schemafull: boolPtr(true),
				Kind:       strPtr("data"),
				Visibility: strPtr("shared"),
				Fields:     []*gql_model.FieldDefInput{{Name: "body", Type: "string"}},
			},
		},
	}
	tables, err := rewriteSchemaInput(input)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	checks := []string{
		"DEFINE TABLE IF NOT EXISTS `doc_grant` SCHEMAFULL;",
		"DEFINE FIELD OVERWRITE `row` ON `doc_grant` TYPE record<`doc`> READONLY;",
		"DEFINE FIELD OVERWRITE `grantee_user_id` ON `doc_grant` TYPE string READONLY;",
		"DEFINE INDEX OVERWRITE `idx_doc_grant_unique` ON `doc_grant` FIELDS `row`, `grantee_user_id` UNIQUE;",
	}
	for _, c := range checks {
		if !ddlContains(tables[0].ddl, c) {
			t.Errorf("shared table missing grant DDL %q; ddl=%v", c, tables[0].ddl)
		}
	}
}

func TestRewritePrivateTableHasNoGrantTable(t *testing.T) {
	input := &gql_model.DatabaseSchemaInput{
		Tables: []*gql_model.TableDefInput{
			{Name: "doc", Kind: strPtr("data"), Fields: []*gql_model.FieldDefInput{{Name: "body", Type: "string"}}},
		},
	}
	tables, err := rewriteSchemaInput(input)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if ddlContains(tables[0].ddl, "doc_grant") {
		t.Errorf("private table must not provision a grant table; ddl=%v", tables[0].ddl)
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
