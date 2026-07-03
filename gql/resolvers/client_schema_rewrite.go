package gql

import (
	"fmt"
	"regexp"
	"strings"

	gql_model "github.com/neoworks/auth/gql/model"
)

const maxDatabasesPerClient = 5

var clientDBIdentRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

var clientDBBaseTypes = map[string]bool{
	"string": true, "int": true, "float": true, "decimal": true,
	"bool": true, "datetime": true, "duration": true, "bytes": true,
	"uuid": true, "object": true, "any": true,
}

var clientTableKinds = map[string]bool{
	"data": true, "relation": true, "helper": true, "internal": true,
}

var clientTableVisibilities = map[string]bool{
	"private": true, "shared": true, "public": true,
}

func isValidClientDBFieldType(t string) bool {
	t = strings.TrimSpace(t)
	if clientDBBaseTypes[t] {
		return true
	}
	for _, prefix := range []string{"option<", "array<", "set<"} {
		if strings.HasPrefix(t, prefix) && strings.HasSuffix(t, ">") {
			return isValidClientDBFieldType(t[len(prefix) : len(t)-1])
		}
	}
	return false
}

// rewrittenTable is the validated, server-owned classification of one submitted
// table — the metadata recorded in the client_table registry that the data plane
// generates GraphQL from. DDL is no longer generated here: the OpenSchema compiler
// emits the SurrealQL (see compileSchemaSource), and the API applies it verbatim.
type rewrittenTable struct {
	name           string
	kind           string
	versioned      bool
	hasSubjectUser bool
	hasInternal    bool
	subjectPath    string
}

func tableKind(t *gql_model.TableDefInput) string {
	if t.Kind == nil || *t.Kind == "" {
		return "data"
	}
	return *t.Kind
}

func wantsHistory(t *gql_model.TableDefInput) bool {
	return t.History != nil && *t.History
}

// validateSchemaInput checks names, types, kinds, and the subject-traceability
// rule before any DDL is generated. Clients never submit raw SurrealDB schema.
func validateSchemaInput(input *gql_model.DatabaseSchemaInput) error {
	tableNames := map[string]bool{}
	for _, t := range input.Tables {
		if t == nil {
			continue
		}
		if err := validateTableDef(t, tableNames); err != nil {
			return err
		}
	}
	return nil
}

func validateTableDef(t *gql_model.TableDefInput, tableNames map[string]bool) error {
	if !clientDBIdentRegex.MatchString(t.Name) {
		return fmt.Errorf("invalid table name %q", t.Name)
	}
	if tableNames[t.Name] {
		return fmt.Errorf("duplicate table name %q", t.Name)
	}
	tableNames[t.Name] = true

	kind := tableKind(t)
	if !clientTableKinds[kind] {
		return fmt.Errorf("table %q: invalid kind %q", t.Name, kind)
	}
	if vis := tableVisibility(t); !clientTableVisibilities[vis] {
		return fmt.Errorf("table %q: invalid visibility %q", t.Name, vis)
	}
	// Relation/helper tables skip subject_user_id but must stay traceable to a user.
	if (kind == "relation" || kind == "helper") && (t.SubjectPath == nil || strings.TrimSpace(*t.SubjectPath) == "") {
		return fmt.Errorf("table %q: %s tables must set subjectPath so rows trace back to a user", t.Name, kind)
	}
	// Internal rows are org-owned with no per-user author; per-user history does not apply.
	if kind == "internal" && wantsHistory(t) {
		return fmt.Errorf("table %q: internal tables cannot request history", t.Name)
	}

	if err := validateFields(t); err != nil {
		return err
	}
	return validateIndexes(t)
}

func tableVisibility(t *gql_model.TableDefInput) string {
	if t.Visibility == nil || *t.Visibility == "" {
		return "private"
	}
	return *t.Visibility
}

func validateFields(t *gql_model.TableDefInput) error {
	fieldNames := map[string]bool{}
	for _, f := range t.Fields {
		if f == nil {
			continue
		}
		if !clientDBIdentRegex.MatchString(f.Name) {
			return fmt.Errorf("table %q: invalid field name %q", t.Name, f.Name)
		}
		if f.Name == "subject_user_id" || f.Name == "organization_id" {
			return fmt.Errorf("table %q: %s is reserved and injected by the server", t.Name, f.Name)
		}
		if fieldNames[f.Name] {
			return fmt.Errorf("table %q: duplicate field %q", t.Name, f.Name)
		}
		fieldNames[f.Name] = true
		if !isValidClientDBFieldType(f.Type) {
			return fmt.Errorf("table %q field %q: unsupported type %q", t.Name, f.Name, f.Type)
		}
	}
	return nil
}

func validateIndexes(t *gql_model.TableDefInput) error {
	fieldTypes := map[string]string{}
	for _, f := range t.Fields {
		if f != nil {
			fieldTypes[f.Name] = strings.TrimSpace(f.Type)
		}
	}

	idxNames := map[string]bool{}
	for _, idx := range t.Indexes {
		if idx == nil {
			continue
		}
		if !clientDBIdentRegex.MatchString(idx.Name) {
			return fmt.Errorf("table %q: invalid index name %q", t.Name, idx.Name)
		}
		if idxNames[idx.Name] {
			return fmt.Errorf("table %q: duplicate index %q", t.Name, idx.Name)
		}
		idxNames[idx.Name] = true
		if len(idx.Fields) == 0 {
			return fmt.Errorf("table %q index %q: no fields specified", t.Name, idx.Name)
		}
		for _, f := range idx.Fields {
			if !clientDBIdentRegex.MatchString(f) {
				return fmt.Errorf("table %q index %q: invalid field %q", t.Name, idx.Name, f)
			}
		}
		// Fulltext indexes only make sense over string fields.
		if isFulltextIndex(idx) {
			for _, f := range idx.Fields {
				if fieldTypes[f] != "string" {
					return fmt.Errorf("table %q index %q: fulltext requires string fields, %q is %q",
						t.Name, idx.Name, f, fieldTypes[f])
				}
			}
		}
	}
	return nil
}

// rewriteSchemaInput validates the compiled schema and classifies each table into
// the registry metadata the data plane consumes. It no longer generates DDL — the
// OpenSchema compiler emits the SurrealQL (compileSchemaSource returns it); this
// remains the server-side validation authority over what the compiler produced.
func rewriteSchemaInput(input *gql_model.DatabaseSchemaInput) ([]rewrittenTable, error) {
	if err := validateSchemaInput(input); err != nil {
		return nil, err
	}

	var out []rewrittenTable
	for _, t := range input.Tables {
		if t == nil {
			continue
		}
		out = append(out, rewriteTable(t))
	}
	return out, nil
}

func rewriteTable(t *gql_model.TableDefInput) rewrittenTable {
	kind := tableKind(t)
	rt := rewrittenTable{
		name:           t.Name,
		kind:           kind,
		versioned:      wantsHistory(t),
		hasSubjectUser: kind == "data",
		hasInternal:    kind == "internal",
	}
	if t.SubjectPath != nil {
		rt.subjectPath = *t.SubjectPath
	}
	return rt
}

// isFulltextIndex reports whether an index is a BM25 fulltext index (validation
// only; the compiler emits the actual index DDL).
func isFulltextIndex(idx *gql_model.IndexDefInput) bool {
	return idx.Fulltext != nil && *idx.Fulltext
}
