package dataplane

import (
	"context"
	"strings"
	"testing"

	"github.com/graphql-go/graphql"
)

// mockQuerier captures the last query + params so tests can assert the SQL the
// resolvers build for shared vs subject-scoped tables.
type mockQuerier struct {
	lastQuery  string
	lastParams map[string]any
	rows       []map[string]any
}

func (m *mockQuerier) QueryClientDB(_ context.Context, _, _, query string, params map[string]any) ([]map[string]any, error) {
	m.lastQuery = query
	m.lastParams = params
	return m.rows, nil
}

func (m *mockQuerier) QueryClientDBLast(_ context.Context, _, _, query string, params map[string]any) ([]map[string]any, error) {
	m.lastQuery = query
	m.lastParams = params
	return m.rows, nil
}

// internalPublicSpec is an internal (org-owned), publicly-readable table (the
// registry shape). Internal rows have no per-user/per-org owner column.
func internalPublicSpec() tableSpec {
	return tableSpec{name: "message", internal: true, visibility: visibilityPublic, fields: []fieldSpec{
		{name: "body", typ: "string"},
		{name: "discussion_id", typ: "string"},
	}}
}

// clientCtx is a confidential client-principal request (the client acting as its
// org) — what internal writes require.
func clientCtx() context.Context {
	return withRequest(context.Background(), requestInfo{dbName: "db", clientOrg: "neoworks", clientPrincipal: true})
}

func resolveParams(ctx context.Context, args map[string]any) graphql.ResolveParams {
	return graphql.ResolveParams{Context: ctx, Args: args}
}

func TestParseRegistrySchemaInternalFlag(t *testing.T) {
	validated := map[string]any{
		"name":       "message",
		"visibility": "public",
		"fields": []any{
			map[string]any{"name": "body", "type": "string"},
			map[string]any{"name": "organization_id", "type": "string"}, // reserved, must be skipped
		},
	}
	spec, err := parseRegistrySchema("internal", false, validated)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !spec.internal {
		t.Error("internal flag not set for kind=internal")
	}
	if !spec.publicRead() {
		t.Error("visibility=public not parsed")
	}
	for _, f := range spec.fields {
		if f.name == "organization_id" {
			t.Fatal("organization_id leaked into spec")
		}
	}
	if len(spec.fields) != 1 {
		t.Errorf("got %d fields, want 1", len(spec.fields))
	}
}

func TestBuildSchemaInternalExposesTimestampsNotOwner(t *testing.T) {
	schema, err := buildSchema(nil, []tableSpec{internalPublicSpec()})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	obj := schema.Type("message").(*graphql.Object)
	fields := obj.Fields()
	for _, name := range []string{"created_at", "updated_at", "body"} {
		if _, ok := fields[name]; !ok {
			t.Errorf("internal object missing %q", name)
		}
	}
	// Internal tables carry no owner column, so organization_id is never exposed.
	if _, ok := fields["organization_id"]; ok {
		t.Error("internal object must not expose organization_id")
	}
}

func TestInternalPublicListHasNoOwnerFilter(t *testing.T) {
	m := &mockQuerier{}
	ctx := withRequest(context.Background(), requestInfo{dbName: "db"}) // anonymous
	if _, err := listResolver(m, internalPublicSpec())(resolveParams(ctx, map[string]any{})); err != nil {
		t.Fatalf("list: %v", err)
	}
	if strings.Contains(m.lastQuery, "subject_user_id") || strings.Contains(m.lastQuery, "organization_id") {
		t.Errorf("internal+public list must not filter by an owner: %s", m.lastQuery)
	}
}

func TestInternalPrivateListDeniesAnonymous(t *testing.T) {
	spec := internalPublicSpec()
	spec.visibility = visibilityPrivate
	m := &mockQuerier{rows: []map[string]any{{"id": "message:1"}}}
	ctx := withRequest(context.Background(), requestInfo{dbName: "db"}) // anonymous
	rows, err := listResolver(m, spec)(resolveParams(ctx, map[string]any{}))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if m.lastQuery != "" {
		t.Errorf("internal+private anon read must not hit the DB: %s", m.lastQuery)
	}
	if list, _ := rows.([]map[string]any); len(list) != 0 {
		t.Errorf("internal+private anon read must be empty, got %v", rows)
	}
}

func TestDataListKeepsSubjectFilter(t *testing.T) {
	m := &mockQuerier{}
	ctx := withRequest(context.Background(), requestInfo{uid: "user-1", dbName: "db"})
	if _, err := listResolver(m, dataSpec())(resolveParams(ctx, map[string]any{})); err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(m.lastQuery, "subject_user_id = $owner") {
		t.Errorf("data list must filter by subject_user_id: %s", m.lastQuery)
	}
}

func TestInternalCreateStampsNoOwner(t *testing.T) {
	m := &mockQuerier{rows: []map[string]any{{"id": "message:1"}}}
	args := map[string]any{"input": map[string]any{"body": "hi"}}
	if _, err := createResolver(m, internalPublicSpec())(resolveParams(clientCtx(), args)); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Internal rows have no owner column: neither ownership field is written.
	if strings.Contains(m.lastQuery, "organization_id") || strings.Contains(m.lastQuery, "subject_user_id") {
		t.Errorf("internal create must not stamp an owner: %s", m.lastQuery)
	}
	if _, ok := m.lastParams["owner"]; ok {
		t.Errorf("internal create must not bind an owner param: %v", m.lastParams["owner"])
	}
}

func TestInternalWriteRequiresClientPrincipal(t *testing.T) {
	m := &mockQuerier{}
	// A user token (uid set, not a client principal) may not write an internal table.
	ctx := withRequest(context.Background(), requestInfo{uid: "user-1", dbName: "db", clientOrg: "neoworks"})
	args := map[string]any{"input": map[string]any{"body": "hi"}}
	if _, err := createResolver(m, internalPublicSpec())(resolveParams(ctx, args)); err == nil {
		t.Error("internal create with a user token must be rejected")
	}
	if m.lastQuery != "" {
		t.Errorf("rejected internal write must not hit the DB: %s", m.lastQuery)
	}
}

func TestInternalUpdateAndDeleteHaveNoOwnerFilter(t *testing.T) {
	ctx := clientCtx()

	mu := &mockQuerier{rows: []map[string]any{{"id": "message:1"}}}
	updArgs := map[string]any{"id": "1", "input": map[string]any{"body": "edited"}}
	if _, err := updateResolver(mu, internalPublicSpec())(resolveParams(ctx, updArgs)); err != nil {
		t.Fatalf("update: %v", err)
	}
	if strings.Contains(mu.lastQuery, "organization_id") || strings.Contains(mu.lastQuery, "subject_user_id") {
		t.Errorf("internal update must not scope to an owner: %s", mu.lastQuery)
	}

	md := &mockQuerier{rows: []map[string]any{{"id": "message:1"}}}
	if _, err := deleteResolver(md, internalPublicSpec())(resolveParams(ctx, map[string]any{"id": "1"})); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if strings.Contains(md.lastQuery, "organization_id") || strings.Contains(md.lastQuery, "subject_user_id") {
		t.Errorf("internal delete must not scope to an owner: %s", md.lastQuery)
	}
}

func TestUserSharedReadAdmitsOwnerAndGrantees(t *testing.T) {
	spec := tableSpec{name: "doc", visibility: visibilityShared, fields: []fieldSpec{{name: "body", typ: "string"}}}
	m := &mockQuerier{}
	ctx := withRequest(context.Background(), requestInfo{uid: "user-1", dbName: "db"})
	if _, err := listResolver(m, spec)(resolveParams(ctx, map[string]any{})); err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(m.lastQuery, "subject_user_id = $owner") {
		t.Errorf("shared read must admit the owner: %s", m.lastQuery)
	}
	if !strings.Contains(m.lastQuery, "SELECT VALUE `row` FROM `doc_grant` WHERE grantee_user_id = $grantee") {
		t.Errorf("shared read must admit grantees: %s", m.lastQuery)
	}
}

func TestSharedTableExposesGrantMutations(t *testing.T) {
	spec := tableSpec{name: "doc", visibility: visibilityShared, fields: []fieldSpec{{name: "body", typ: "string"}}}
	schema, err := buildSchema(nil, []tableSpec{spec})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	m := schema.MutationType().Fields()
	for _, name := range []string{"grantDoc", "revokeDoc"} {
		if _, ok := m[name]; !ok {
			t.Errorf("shared table missing mutation %q", name)
		}
	}
}

func TestPrivateTableHasNoGrantMutations(t *testing.T) {
	spec := tableSpec{name: "doc", visibility: visibilityPrivate, fields: []fieldSpec{{name: "body", typ: "string"}}}
	schema, err := buildSchema(nil, []tableSpec{spec})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, ok := schema.MutationType().Fields()["grantDoc"]; ok {
		t.Error("private table must not expose grant mutations")
	}
}

func TestGrantRequiresRowOwnership(t *testing.T) {
	spec := tableSpec{name: "doc", visibility: visibilityShared, fields: []fieldSpec{{name: "body", typ: "string"}}}
	// Ownership probe returns no rows → caller does not own the row → forbidden.
	m := &mockQuerier{rows: []map[string]any{}}
	ctx := withRequest(context.Background(), requestInfo{uid: "user-1", dbName: "db"})
	args := map[string]any{"id": "1", "userId": "user-2"}
	got, err := grantResolver(m, spec)(resolveParams(ctx, args))
	if err == nil {
		t.Error("granting on a row the caller does not own must error")
	}
	if got != false {
		t.Errorf("grant result = %v, want false", got)
	}
}

func TestContainsMutation(t *testing.T) {
	cases := map[string]bool{
		"query { messages { id } }":            false,
		"{ messages { id } }":                  false,
		"mutation { createMessage { id } }":    true,
		"query Q { a } mutation M { b }":       true,
		"not a valid graphql document at all!": true, // fail safe → require auth
	}
	for q, want := range cases {
		if got := containsMutation(q); got != want {
			t.Errorf("containsMutation(%q) = %v, want %v", q, got, want)
		}
	}
}
