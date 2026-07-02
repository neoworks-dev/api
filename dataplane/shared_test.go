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

// orgPublicSpec is an org-scoped, publicly-readable table (the registry shape).
func orgPublicSpec() tableSpec {
	return tableSpec{name: "message", org: true, visibility: visibilityPublic, fields: []fieldSpec{
		{name: "body", typ: "string"},
		{name: "discussion_id", typ: "string"},
	}}
}

// clientCtx is a confidential client-principal request (the client acting as its
// org) — what org-scoped writes require.
func clientCtx() context.Context {
	return withRequest(context.Background(), requestInfo{dbName: "db", clientOrg: "neoworks", clientPrincipal: true})
}

func resolveParams(ctx context.Context, args map[string]any) graphql.ResolveParams {
	return graphql.ResolveParams{Context: ctx, Args: args}
}

func TestParseRegistrySchemaOrgFlag(t *testing.T) {
	validated := map[string]any{
		"name":       "message",
		"visibility": "public",
		"fields": []any{
			map[string]any{"name": "body", "type": "string"},
			map[string]any{"name": "organization_id", "type": "string"}, // reserved, must be skipped
		},
	}
	spec, err := parseRegistrySchema("org", false, validated)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !spec.org {
		t.Error("org flag not set for kind=org")
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

func TestBuildSchemaOrgExposesOrganizationAndTimestamps(t *testing.T) {
	schema, err := buildSchema(nil, []tableSpec{orgPublicSpec()})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	obj := schema.Type("message").(*graphql.Object)
	fields := obj.Fields()
	for _, name := range []string{"organization_id", "created_at", "updated_at", "body"} {
		if _, ok := fields[name]; !ok {
			t.Errorf("org object missing %q", name)
		}
	}
	// organization_id is server-managed, never writable.
	createInput := schema.Type("messageCreateInput").(*graphql.InputObject)
	if _, ok := createInput.Fields()["organization_id"]; ok {
		t.Error("organization_id must not be writable")
	}
}

func TestOrgPublicListHasNoOwnerFilter(t *testing.T) {
	m := &mockQuerier{}
	ctx := withRequest(context.Background(), requestInfo{dbName: "db"}) // anonymous
	if _, err := listResolver(m, orgPublicSpec())(resolveParams(ctx, map[string]any{})); err != nil {
		t.Fatalf("list: %v", err)
	}
	if strings.Contains(m.lastQuery, "subject_user_id") || strings.Contains(m.lastQuery, "organization_id") {
		t.Errorf("org+public list must not filter by an owner: %s", m.lastQuery)
	}
}

func TestOrgPrivateListDeniesAnonymous(t *testing.T) {
	spec := orgPublicSpec()
	spec.visibility = visibilityPrivate
	m := &mockQuerier{rows: []map[string]any{{"id": "message:1"}}}
	ctx := withRequest(context.Background(), requestInfo{dbName: "db"}) // anonymous
	rows, err := listResolver(m, spec)(resolveParams(ctx, map[string]any{}))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if m.lastQuery != "" {
		t.Errorf("org+private anon read must not hit the DB: %s", m.lastQuery)
	}
	if list, _ := rows.([]map[string]any); len(list) != 0 {
		t.Errorf("org+private anon read must be empty, got %v", rows)
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

func TestOrgCreateStampsOrganization(t *testing.T) {
	m := &mockQuerier{rows: []map[string]any{{"id": "message:1"}}}
	args := map[string]any{"input": map[string]any{"body": "hi"}}
	if _, err := createResolver(m, orgPublicSpec())(resolveParams(clientCtx(), args)); err != nil {
		t.Fatalf("create: %v", err)
	}
	if !strings.Contains(m.lastQuery, "organization_id = $owner") {
		t.Errorf("org create must stamp organization_id: %s", m.lastQuery)
	}
	if strings.Contains(m.lastQuery, "subject_user_id") {
		t.Errorf("org create must not stamp subject_user_id: %s", m.lastQuery)
	}
	if m.lastParams["owner"] != "neoworks" {
		t.Errorf("owner not bound to clientOrg: %v", m.lastParams["owner"])
	}
}

func TestOrgWriteRequiresClientPrincipal(t *testing.T) {
	m := &mockQuerier{}
	// A user token (uid set, not a client principal) may not write an org table.
	ctx := withRequest(context.Background(), requestInfo{uid: "user-1", dbName: "db", clientOrg: "neoworks"})
	args := map[string]any{"input": map[string]any{"body": "hi"}}
	if _, err := createResolver(m, orgPublicSpec())(resolveParams(ctx, args)); err == nil {
		t.Error("org create with a user token must be rejected")
	}
	if m.lastQuery != "" {
		t.Errorf("rejected org write must not hit the DB: %s", m.lastQuery)
	}
}

func TestOrgUpdateAndDeleteScopeToOrganization(t *testing.T) {
	ctx := clientCtx()

	mu := &mockQuerier{rows: []map[string]any{{"id": "message:1"}}}
	updArgs := map[string]any{"id": "1", "input": map[string]any{"body": "edited"}}
	if _, err := updateResolver(mu, orgPublicSpec())(resolveParams(ctx, updArgs)); err != nil {
		t.Fatalf("update: %v", err)
	}
	if !strings.Contains(mu.lastQuery, "organization_id = $owner") {
		t.Errorf("org update must scope to organization_id: %s", mu.lastQuery)
	}

	md := &mockQuerier{rows: []map[string]any{{"id": "message:1"}}}
	if _, err := deleteResolver(md, orgPublicSpec())(resolveParams(ctx, map[string]any{"id": "1"})); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !strings.Contains(md.lastQuery, "organization_id = $owner") {
		t.Errorf("org delete must scope to organization_id: %s", md.lastQuery)
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
