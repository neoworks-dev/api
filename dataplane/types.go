package dataplane

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/graphql-go/graphql"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// identRegex mirrors the server-side validator (client_schema_rewrite.go). Names
// in the registry were already validated at provision time; we re-check as
// defense in depth before interpolating any identifier into SurrealQL.
var identRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// fieldSpec is one column of a client table: its name and SurrealDB type string
// (e.g. "string", "option<int>", "array<float>", "object").
type fieldSpec struct {
	name string
	typ  string
}

// tableSpec is the validated, server-owned form of one client table used to
// generate GraphQL types and resolvers. Ownership (`org`) and `visibility` are
// the two access axes:
//   - org == false → user-scoped: every row carries subject_user_id (the user).
//   - org == true  → org-scoped: every row carries organization_id (the org that
//     owns the request's client). Writes require a client-principal token.
//   - visibility ∈ {private, shared, public} controls who may read.
type tableSpec struct {
	name       string
	versioned  bool
	org        bool
	visibility string
	fields     []fieldSpec
	// searchFields are the string fields covered by a FULLTEXT index, in index
	// declaration order. When non-empty, the list query exposes a `search` arg.
	searchFields []string
}

const (
	visibilityPrivate = "private"
	visibilityShared  = "shared"
	visibilityPublic  = "public"
)

func (s tableSpec) publicRead() bool { return s.visibility == visibilityPublic }
func (s tableSpec) sharedRead() bool { return s.visibility == visibilityShared }

// needsTimestamps mirrors the provisioning rule: org tables and any non-private
// table carry server-managed created_at/updated_at.
func (s tableSpec) needsTimestamps() bool {
	return s.org || s.visibility != visibilityPrivate
}

// idString renders a record id as its bare identifier, dropping the `table:`
// prefix (matches gql/resolvers/types.go).
func idString(rid models.RecordID) string {
	return fmt.Sprintf("%v", rid.ID)
}

// parseRegistrySchema reads a `client_table.validated_schema` object (decoded as
// a generic map) into a tableSpec. The schema is the submitted TableDefInput:
// { name, fields: [{name, type}], ... }. subject_user_id is never present (it is
// reserved/injected) and is never surfaced.
func parseRegistrySchema(kind string, versioned bool, validated map[string]any) (tableSpec, error) {
	name, _ := validated["name"].(string)
	if !identRegex.MatchString(name) {
		return tableSpec{}, fmt.Errorf("invalid table name %q", name)
	}

	visibility := visibilityPrivate
	if v, ok := validated["visibility"].(string); ok && v != "" {
		visibility = v
	}
	spec := tableSpec{name: name, versioned: versioned, org: kind == "org", visibility: visibility}

	rawFields, _ := validated["fields"].([]any)
	for _, rf := range rawFields {
		fm, ok := rf.(map[string]any)
		if !ok {
			continue
		}
		fname, _ := fm["name"].(string)
		ftype, _ := fm["type"].(string)
		if !identRegex.MatchString(fname) {
			return tableSpec{}, fmt.Errorf("table %q: invalid field name %q", name, fname)
		}
		if fname == "subject_user_id" || fname == "organization_id" {
			continue // reserved, surfaced via the object type, never from validated fields
		}
		if !isValidFieldType(ftype) {
			return tableSpec{}, fmt.Errorf("table %q field %q: unsupported type %q", name, fname, ftype)
		}
		spec.fields = append(spec.fields, fieldSpec{name: fname, typ: strings.TrimSpace(ftype)})
	}

	spec.searchFields = parseSearchFields(validated)
	return spec, nil
}

// parseSearchFields collects the string fields covered by fulltext indexes from
// the submitted index definitions. Field names are re-validated as defense in
// depth before they ever reach a SurrealQL `@@` clause.
func parseSearchFields(validated map[string]any) []string {
	rawIndexes, _ := validated["indexes"].([]any)
	seen := map[string]bool{}
	var out []string
	for _, ri := range rawIndexes {
		im, ok := ri.(map[string]any)
		if !ok {
			continue
		}
		fulltext, _ := im["fulltext"].(bool)
		if !fulltext {
			continue
		}
		rawFields, _ := im["fields"].([]any)
		for _, rf := range rawFields {
			fname, _ := rf.(string)
			if !identRegex.MatchString(fname) || seen[fname] {
				continue
			}
			seen[fname] = true
			out = append(out, fname)
		}
	}
	return out
}

var baseTypes = map[string]bool{
	"string": true, "int": true, "float": true, "decimal": true,
	"bool": true, "datetime": true, "duration": true, "bytes": true,
	"uuid": true, "object": true, "any": true,
}

func isValidFieldType(t string) bool {
	t = strings.TrimSpace(t)
	if baseTypes[t] {
		return true
	}
	for _, prefix := range []string{"option<", "array<", "set<"} {
		if strings.HasPrefix(t, prefix) && strings.HasSuffix(t, ">") {
			return isValidFieldType(t[len(prefix) : len(t)-1])
		}
	}
	return false
}

// unwrapOption strips a single leading `option<...>` wrapper, returning the inner
// type and whether the field is nullable.
func unwrapOption(t string) (inner string, optional bool) {
	t = strings.TrimSpace(t)
	if strings.HasPrefix(t, "option<") && strings.HasSuffix(t, ">") {
		return strings.TrimSpace(t[len("option<") : len(t)-1]), true
	}
	return t, false
}

// graphQLType maps a SurrealDB field type to a GraphQL type usable for both
// inputs and outputs (all leaves are scalars). decimal -> String to preserve
// precision; object/any -> JSON; array<T>/set<T> -> List(T).
func graphQLType(t string) graphql.Type {
	t = strings.TrimSpace(t)
	if inner, optional := unwrapOption(t); optional {
		return graphQLType(inner)
	}
	for _, prefix := range []string{"array<", "set<"} {
		if strings.HasPrefix(t, prefix) && strings.HasSuffix(t, ">") {
			return graphql.NewList(graphQLType(t[len(prefix) : len(t)-1]))
		}
	}
	switch t {
	case "int":
		return graphql.Int
	case "float":
		return graphql.Float
	case "bool":
		return graphql.Boolean
	case "object", "any":
		return jsonScalar
	default:
		// string, uuid, duration, datetime, decimal, bytes
		return graphql.String
	}
}

// isScalarFilterable reports whether a field type supports an equality filter
// (scalars only; object/any/list excluded in v1).
func isScalarFilterable(t string) bool {
	inner, _ := unwrapOption(t)
	switch inner {
	case "string", "int", "float", "decimal", "bool", "datetime", "duration", "uuid":
		return true
	default:
		return false
	}
}

// isDatetime reports whether a (possibly optional) field is a datetime, which
// needs a `<datetime>` cast when written.
func isDatetime(t string) bool {
	inner, _ := unwrapOption(t)
	return inner == "datetime"
}
