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
	"data": true, "relation": true, "helper": true, "org": true,
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

// rewrittenTable is the validated, server-owned form of one submitted table.
// It carries the DDL applied to the isolated client database and the metadata
// recorded in the client_table registry.
type rewrittenTable struct {
	name           string
	kind           string
	versioned      bool
	hasSubjectUser bool
	hasOrg         bool
	subjectPath    string
	ddl            []string
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
	// Org-scoped rows are owned by the organization; per-user history does not apply.
	if kind == "org" && wantsHistory(t) {
		return fmt.Errorf("table %q: org-scoped tables cannot request history", t.Name)
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

// rewriteSchemaInput turns validated JSON into the server-owned table forms.
// Data tables get a subject_user_id field; tables that request history are
// rewritten into the versioned triple (current + _version + derived_from).
func rewriteSchemaInput(input *gql_model.DatabaseSchemaInput) ([]rewrittenTable, error) {
	if err := validateSchemaInput(input); err != nil {
		return nil, err
	}

	var out []rewrittenTable
	derivedFromEmitted := false
	for _, t := range input.Tables {
		if t == nil {
			continue
		}
		rt := rewriteTable(t)
		// A single shared derived_from relation serves every versioned table in the database.
		if rt.versioned && !derivedFromEmitted {
			rt.ddl = append([]string{"DEFINE TABLE IF NOT EXISTS `derived_from` TYPE RELATION;"}, rt.ddl...)
			derivedFromEmitted = true
		}
		out = append(out, rt)
	}

	// Fulltext indexes reference an analyzer that must exist first. Provision each
	// distinct analyzer ahead of every table's DDL as its own rewritten "table".
	if analyzers := fulltextAnalyzers(input); len(analyzers) > 0 {
		var stmts []string
		for _, name := range analyzers {
			stmts = append(stmts, analyzerDDL(name))
		}
		out = append([]rewrittenTable{{name: "_analyzers", ddl: stmts}}, out...)
	}
	return out, nil
}

// fulltextAnalyzers collects the distinct analyzer names used by fulltext indexes
// across the submitted tables, in first-seen order.
func fulltextAnalyzers(input *gql_model.DatabaseSchemaInput) []string {
	seen := map[string]bool{}
	var names []string
	for _, t := range input.Tables {
		if t == nil {
			continue
		}
		for _, idx := range t.Indexes {
			if idx == nil || !isFulltextIndex(idx) {
				continue
			}
			name := analyzerFor(idx)
			if seen[name] {
				continue
			}
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

func rewriteTable(t *gql_model.TableDefInput) rewrittenTable {
	kind := tableKind(t)
	rt := rewrittenTable{
		name:           t.Name,
		kind:           kind,
		versioned:      wantsHistory(t),
		hasSubjectUser: kind == "data",
		hasOrg:         kind == "org",
	}
	if t.SubjectPath != nil {
		rt.subjectPath = *t.SubjectPath
	}

	// Non-private tables (public/shared) and org tables carry server timestamps so
	// callers can sort by recency; private user data does not (it never has).
	needsTimestamps := rt.hasOrg || tableVisibility(t) != "private"

	if rt.versioned {
		rt.ddl = versionedTableDDL(t, rt.hasSubjectUser)
	} else {
		rt.ddl = plainTableDDL(t, rt.hasSubjectUser, rt.hasOrg, needsTimestamps)
	}
	// A "shared" table grants read access to specific users via a companion grant
	// table (owner-managed). Modeled on media_grant.
	if tableVisibility(t) == "shared" {
		rt.ddl = append(rt.ddl, grantTableDDL(t.Name)...)
	}
	return rt
}

// grantTableDDL provisions the `<table>_grant` relation backing a shared table:
// (row, grantee_user_id) pairs, unique per pair, indexed for the read subquery.
func grantTableDDL(table string) []string {
	grant := table + "_grant"
	return []string{
		fmt.Sprintf("DEFINE TABLE IF NOT EXISTS `%s` SCHEMAFULL;", grant),
		fmt.Sprintf("DEFINE FIELD OVERWRITE `row` ON `%s` TYPE record<`%s`> READONLY;", grant, table),
		fmt.Sprintf("DEFINE FIELD OVERWRITE `grantee_user_id` ON `%s` TYPE string READONLY;", grant),
		fmt.Sprintf("DEFINE FIELD OVERWRITE `created_at` ON `%s` TYPE datetime VALUE time::now() READONLY;", grant),
		fmt.Sprintf("DEFINE INDEX OVERWRITE `idx_%s_unique` ON `%s` FIELDS `row`, `grantee_user_id` UNIQUE;", grant, grant),
		fmt.Sprintf("DEFINE INDEX OVERWRITE `idx_%s_grantee` ON `%s` FIELDS `grantee_user_id`;", grant, grant),
	}
}

func tableKeyword(t *gql_model.TableDefInput) string {
	if t.Schemafull != nil && *t.Schemafull {
		return "SCHEMAFULL"
	}
	return "SCHEMALESS"
}

// fieldTypeNeedsFlexible reports whether a type needs FLEXIBLE so SurrealDB
// permits arbitrary nested content on a SCHEMAFULL table (object/any, including
// when wrapped in option/array/set).
func fieldTypeNeedsFlexible(t string) bool {
	t = strings.TrimSpace(t)
	for _, p := range []string{"option<", "array<", "set<"} {
		if strings.HasPrefix(t, p) && strings.HasSuffix(t, ">") {
			return fieldTypeNeedsFlexible(t[len(p) : len(t)-1])
		}
	}
	return t == "object" || t == "any"
}

// fieldDDL emits an OVERWRITE field definition (so schema updates re-apply
// cleanly), adding FLEXIBLE for object/any types and an optional trailing clause.
func fieldDDL(table, name, typ, suffix string) string {
	flexible := ""
	if fieldTypeNeedsFlexible(typ) {
		flexible = " FLEXIBLE" // SurrealDB requires FLEXIBLE after the TYPE clause
	}
	if suffix != "" {
		suffix = " " + suffix
	}
	return fmt.Sprintf("DEFINE FIELD OVERWRITE `%s` ON `%s` TYPE %s%s%s;", name, table, typ, flexible, suffix)
}

// defaultAnalyzer is the built-in fulltext analyzer provisioned per client DB
// whenever any table declares a fulltext index. Recipe mirrors the contacts FTS
// analyzer migration (blank/class tokenizers, lowercase/ascii/snowball filters).
const defaultAnalyzer = "text_en"

func isFulltextIndex(idx *gql_model.IndexDefInput) bool {
	return idx.Fulltext != nil && *idx.Fulltext
}

func analyzerFor(idx *gql_model.IndexDefInput) string {
	if idx.Analyzer != nil && strings.TrimSpace(*idx.Analyzer) != "" {
		return strings.TrimSpace(*idx.Analyzer)
	}
	return defaultAnalyzer
}

func analyzerDDL(name string) string {
	return fmt.Sprintf("DEFINE ANALYZER OVERWRITE `%s` TOKENIZERS blank, class FILTERS lowercase, ascii, snowball(english);", name)
}

func indexDDL(table string, idx *gql_model.IndexDefInput) string {
	quoted := make([]string, len(idx.Fields))
	for i, f := range idx.Fields {
		quoted[i] = "`" + f + "`"
	}
	fields := strings.Join(quoted, ", ")

	if isFulltextIndex(idx) {
		return fmt.Sprintf("DEFINE INDEX OVERWRITE `%s` ON `%s` FIELDS %s FULLTEXT ANALYZER `%s` BM25 HIGHLIGHTS;",
			idx.Name, table, fields, analyzerFor(idx))
	}

	unique := ""
	if idx.Unique != nil && *idx.Unique {
		unique = " UNIQUE"
	}
	return fmt.Sprintf("DEFINE INDEX OVERWRITE `%s` ON `%s` FIELDS %s%s;",
		idx.Name, table, fields, unique)
}

func subjectIndexDDL(table string) string {
	return fmt.Sprintf("DEFINE INDEX OVERWRITE `idx_%s_subject_user` ON `%s` FIELDS `subject_user_id`;", table, table)
}

func plainTableDDL(t *gql_model.TableDefInput, injectSubject, injectOrg, injectTimestamps bool) []string {
	stmts := []string{fmt.Sprintf("DEFINE TABLE IF NOT EXISTS `%s` %s;", t.Name, tableKeyword(t))}
	if injectSubject {
		stmts = append(stmts,
			fieldDDL(t.Name, "subject_user_id", "string", ""),
			subjectIndexDDL(t.Name),
		)
	}
	// Org-scoped tables are owned by the organization behind the request's client:
	// stamp organization_id server-side.
	if injectOrg {
		stmts = append(stmts,
			fieldDDL(t.Name, "organization_id", "option<string>", ""),
			fmt.Sprintf("DEFINE INDEX OVERWRITE `idx_%s_org` ON `%s` FIELDS `organization_id`;", t.Name, t.Name),
		)
	}
	for _, f := range t.Fields {
		if f == nil {
			continue
		}
		stmts = append(stmts, fieldDDL(t.Name, f.Name, f.Type, ""))
	}
	if injectTimestamps {
		stmts = append(stmts,
			fmt.Sprintf("DEFINE FIELD OVERWRITE `created_at` ON `%s` TYPE datetime VALUE $before OR time::now() READONLY;", t.Name),
			fmt.Sprintf("DEFINE FIELD OVERWRITE `updated_at` ON `%s` TYPE datetime VALUE time::now();", t.Name),
		)
	}
	for _, idx := range t.Indexes {
		if idx == nil {
			continue
		}
		stmts = append(stmts, indexDDL(t.Name, idx))
	}
	return stmts
}

// versionedTableDDL emits the current table, the append-only _version table, and
// the version pointer, following the project's versioning convention.
func versionedTableDDL(t *gql_model.TableDefInput, injectSubject bool) []string {
	current := t.Name
	history := t.Name + "_version"

	stmts := []string{fmt.Sprintf("DEFINE TABLE IF NOT EXISTS `%s` %s;", current, tableKeyword(t))}
	if injectSubject {
		stmts = append(stmts,
			fieldDDL(current, "subject_user_id", "string", ""),
			subjectIndexDDL(current),
		)
	}
	for _, f := range t.Fields {
		if f == nil {
			continue
		}
		stmts = append(stmts, fieldDDL(current, f.Name, f.Type, ""))
	}
	stmts = append(stmts,
		fmt.Sprintf("DEFINE FIELD OVERWRITE `created_at` ON `%s` TYPE datetime VALUE $before OR time::now() READONLY;", current),
		fmt.Sprintf("DEFINE FIELD OVERWRITE `updated_at` ON `%s` TYPE datetime VALUE time::now();", current),
		fmt.Sprintf("DEFINE FIELD OVERWRITE `version` ON `%s` TYPE option<record<`%s`>>;", current, history),
	)
	for _, idx := range t.Indexes {
		if idx == nil {
			continue
		}
		stmts = append(stmts, indexDDL(current, idx))
	}

	// Append-only history table: data fields mirrored as READONLY.
	stmts = append(stmts, fmt.Sprintf("DEFINE TABLE IF NOT EXISTS `%s` %s;", history, tableKeyword(t)))
	stmts = append(stmts, fmt.Sprintf("DEFINE FIELD OVERWRITE `%s_id` ON `%s` TYPE record<`%s`> READONLY;", current, history, current))
	if injectSubject {
		stmts = append(stmts, fieldDDL(history, "subject_user_id", "string", "READONLY"))
	}
	for _, f := range t.Fields {
		if f == nil {
			continue
		}
		stmts = append(stmts, fieldDDL(history, f.Name, f.Type, "READONLY"))
	}
	stmts = append(stmts,
		fmt.Sprintf("DEFINE FIELD OVERWRITE `created_at` ON `%s` TYPE datetime VALUE time::now() READONLY;", history),
		fmt.Sprintf("DEFINE INDEX OVERWRITE `idx_%s_parent` ON `%s` FIELDS `%s_id`;", history, history, current),
	)
	return stmts
}

// allDDL flattens the per-table DDL in submission order.
func allDDL(tables []rewrittenTable) []string {
	var out []string
	for _, rt := range tables {
		out = append(out, rt.ddl...)
	}
	return out
}
