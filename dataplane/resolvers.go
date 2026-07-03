package dataplane

import (
	"context"
	"fmt"
	"strings"

	"github.com/graphql-go/graphql"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// Querier runs parametrized queries against a named client database. Implemented
// by *database.SurrealStore; an interface keeps the engine testable.
type Querier interface {
	QueryClientDB(ctx context.Context, namespace, dbName, query string, params map[string]any) ([]map[string]any, error)
	QueryClientDBLast(ctx context.Context, namespace, dbName, query string, params map[string]any) ([]map[string]any, error)
}

// dbCoords returns the (namespace, database) the request resolved to, threaded
// through context by the handler.
func dbCoords(ctx context.Context) (namespace, dbName string) {
	return namespaceFromContext(ctx), dbNameFromContext(ctx)
}

// fieldResolver reads one column from the row map and normalizes it (record ids,
// datetimes) for the GraphQL layer.
func fieldResolver(key string) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) {
		m, ok := p.Source.(map[string]any)
		if !ok {
			return nil, nil
		}
		return convertValue(m[key]), nil
	}
}

func quote(ident string) string { return "`" + ident + "`" }

// buildAssignments turns provided input into a SET clause fragment. coalesce
// emits `field = $f_field ?? $current.field` (versioned update); otherwise it
// emits direct assignments for present fields only, casting datetimes.
func buildAssignments(spec tableSpec, input map[string]any, coalesce bool) ([]string, map[string]any) {
	var parts []string
	params := map[string]any{}
	for _, f := range spec.fields {
		val, present := input[f.name]
		if coalesce {
			parts = append(parts, fmt.Sprintf("%s = $f_%s ?? $current.%s", quote(f.name), f.name, quote(f.name)))
			params["f_"+f.name] = val // nil when absent -> coalesces to current
			continue
		}
		if !present {
			continue
		}
		if isDatetime(f.typ) {
			parts = append(parts, fmt.Sprintf("%s = <datetime>$f_%s", quote(f.name), f.name))
		} else {
			parts = append(parts, fmt.Sprintf("%s = $f_%s", quote(f.name), f.name))
		}
		params["f_"+f.name] = val
	}
	return parts, params
}

func inputArg(p graphql.ResolveParams) map[string]any {
	in, _ := p.Args["input"].(map[string]any)
	if in == nil {
		return map[string]any{}
	}
	return in
}

// readScope returns the WHERE fragment (without a leading AND) and params that
// restrict reads to what the caller may see, plus whether any access is possible
// at all. Public is unrestricted; private/shared scope to the owner; shared also
// admits granted users; org-private requires an authenticated caller of the org's
// client.
func readScope(spec tableSpec, ctx context.Context) (clause string, params map[string]any, allowed bool) {
	if spec.publicRead() {
		return "", map[string]any{}, true
	}

	// A user the row was shared with reads it via their own user token.
	grantSub := fmt.Sprintf("id IN (SELECT VALUE `row` FROM %s WHERE grantee_user_id = $grantee)",
		quote(spec.name+"_grant"))
	uid := uidFromContext(ctx)

	if spec.internal {
		// The instance belongs to one organization and internal rows have no per-user
		// owner, so any authenticated caller of the client sees every row.
		if clientPrincipalFromContext(ctx) || authedFromContext(ctx) {
			return "", map[string]any{}, true
		}
		return "", nil, false
	}

	// User-scoped: confined to the owning user (anonymous uid "" matches nothing).
	if spec.sharedRead() {
		return "(subject_user_id = $owner OR " + grantSub + ")",
			map[string]any{"owner": uid, "grantee": uid}, true
	}
	return "subject_user_id = $owner", map[string]any{"owner": uid}, true
}

// writeOwner returns the owner column, its value, and whether the caller is
// allowed to write. Internal tables have no owner column (empty field) and only
// require a client-principal token; user writes stamp/scope by subject_user_id.
func writeOwner(spec tableSpec, ctx context.Context) (field string, value string, allowed bool) {
	if spec.internal {
		if !clientPrincipalFromContext(ctx) {
			return "", "", false
		}
		return "", "", true
	}
	uid := uidFromContext(ctx)
	if uid == "" {
		return "", "", false
	}
	return "subject_user_id", uid, true
}

// ownerAssign returns the leading "field = $owner" SET fragment (and registers the
// param) for tables that have an owner column; empty for internal tables.
func ownerAssign(field, value string, params map[string]any) []string {
	if field == "" {
		return nil
	}
	params["owner"] = value
	return []string{field + " = $owner"}
}

// ownerFilter returns the " AND field = $owner" WHERE fragment (and registers the
// param) for tables that have an owner column; empty for internal tables.
func ownerFilter(field, value string, params map[string]any) string {
	if field == "" {
		return ""
	}
	params["owner"] = value
	return " AND " + field + " = $owner"
}

var errWriteForbidden = fmt.Errorf("not permitted")

// ── Query resolvers ──────────────────────────────────────────────────────────

func getResolver(q Querier, spec tableSpec) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) {
		scope, params, allowed := readScope(spec, p.Context)
		if !allowed {
			return nil, nil
		}
		idArg, _ := p.Args["id"].(string)
		params["id"] = models.NewRecordID(spec.name, idArg)
		where := "id = $id"
		if scope != "" {
			where += " AND " + scope
		}
		ns, db := dbCoords(p.Context)
		rows, err := q.QueryClientDB(p.Context, ns, db,
			fmt.Sprintf("SELECT * FROM %s WHERE %s LIMIT 1", quote(spec.name), where),
			params,
		)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			return nil, nil
		}
		return rows[0], nil
	}
}

func listResolver(q Querier, spec tableSpec) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) {
		scope, params, allowed := readScope(spec, p.Context)
		if !allowed {
			return []map[string]any{}, nil
		}
		var where []string
		if scope != "" {
			where = append(where, scope)
		}

		if filter, ok := p.Args["filter"].(map[string]any); ok {
			for _, f := range spec.fields {
				if !isScalarFilterable(f.typ) {
					continue
				}
				val, present := filter[f.name]
				if !present {
					continue
				}
				if isDatetime(f.typ) {
					where = append(where, fmt.Sprintf("%s = <datetime>$flt_%s", quote(f.name), f.name))
				} else {
					where = append(where, fmt.Sprintf("%s = $flt_%s", quote(f.name), f.name))
				}
				params["flt_"+f.name] = val
			}
		}

		// Fulltext search: rank by summed BM25 score across the indexed fields. Each
		// field gets its own `@N@` reference so `search::score(N)` can address it.
		scoreOrder := ""
		if term, ok := p.Args["search"].(string); ok && strings.TrimSpace(term) != "" && len(spec.searchFields) > 0 {
			var matches, scores []string
			for i, field := range spec.searchFields {
				matches = append(matches, fmt.Sprintf("%s @%d@ $search", quote(field), i))
				scores = append(scores, fmt.Sprintf("search::score(%d)", i))
			}
			where = append(where, "("+strings.Join(matches, " OR ")+")")
			params["search"] = strings.TrimSpace(term)
			scoreOrder = " ORDER BY " + strings.Join(scores, " + ") + " DESC"
		}

		limit := 50
		if l, ok := p.Args["limit"].(int); ok && l > 0 {
			limit = l
		}
		offset := 0
		if o, ok := p.Args["offset"].(int); ok && o > 0 {
			offset = o
		}
		params["limit"] = limit
		params["offset"] = offset

		order := ""
		if spec.versioned || spec.needsTimestamps() {
			order = " ORDER BY created_at DESC"
		}
		// A search query orders by relevance instead of recency.
		if scoreOrder != "" {
			order = scoreOrder
		}
		whereClause := ""
		if len(where) > 0 {
			whereClause = " WHERE " + strings.Join(where, " AND ")
		}
		query := fmt.Sprintf("SELECT * FROM %s%s%s LIMIT $limit START $offset",
			quote(spec.name), whereClause, order)

		ns, db := dbCoords(p.Context)
		rows, err := q.QueryClientDB(p.Context, ns, db, query, params)
		if err != nil {
			return nil, err
		}
		return rows, nil
	}
}

func historyResolver(q Querier, spec tableSpec) graphql.FieldResolveFn {
	history := spec.name + "_version"
	return func(p graphql.ResolveParams) (any, error) {
		uid := uidFromContext(p.Context)
		idArg, _ := p.Args["id"].(string)
		ns, db := dbCoords(p.Context)
		rows, err := q.QueryClientDB(p.Context, ns, db,
			fmt.Sprintf("SELECT * FROM %s WHERE %s = $id AND subject_user_id = $uid ORDER BY created_at DESC",
				quote(history), quote(spec.name+"_id")),
			map[string]any{"id": models.NewRecordID(spec.name, idArg), "uid": uid},
		)
		if err != nil {
			return nil, err
		}
		return rows, nil
	}
}

// ── Mutation resolvers ───────────────────────────────────────────────────────

func createResolver(q Querier, spec tableSpec) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) {
		ownerField, ownerVal, allowed := writeOwner(spec, p.Context)
		if !allowed {
			return nil, errWriteForbidden
		}
		ns, dbName := dbCoords(p.Context)
		assigns, params := buildAssignments(spec, inputArg(p), false)
		setClause := strings.Join(append(ownerAssign(ownerField, ownerVal, params), assigns...), ", ")

		// Optional client-supplied id → use it as the record id.
		idArg, _ := p.Args["id"].(string)

		if !spec.versioned {
			target := quote(spec.name)
			if idArg != "" {
				target = "type::record($tbl, $id)"
				params["tbl"] = spec.name
				params["id"] = idArg
			}
			setSQL := ""
			if setClause != "" {
				setSQL = " SET " + setClause
			}
			rows, err := q.QueryClientDB(p.Context, ns, dbName,
				fmt.Sprintf("CREATE %s%s RETURN AFTER", target, setSQL),
				params,
			)
			if err != nil {
				return nil, err
			}
			if len(rows) == 0 {
				return nil, fmt.Errorf("create %s: no result", spec.name)
			}
			return rows[0], nil
		}

		// Versioned tables are user-scoped (the history triple mirrors subject_user_id).
		// Versioning an internal (org-owned) table is not supported.
		if spec.internal {
			return nil, fmt.Errorf("versioned internal tables are not supported")
		}

		// Versioned: create the history row and the current row in one transaction.
		history := spec.name + "_version"
		cid := "rand::uuid()"
		if idArg != "" {
			cid = "$id"
			params["id"] = idArg
		}
		query := fmt.Sprintf(`
			BEGIN TRANSACTION;
			LET $cid = %s;
			LET $version = (CREATE ONLY %s SET %s = type::record('%s', $cid), subject_user_id = $owner, %s);
			LET $row = CREATE ONLY type::record('%s', $cid) SET subject_user_id = $owner, %s, version = $version.id;
			RETURN [$row];
			COMMIT TRANSACTION;
		`, cid, quote(history), quote(spec.name+"_id"), spec.name, strings.Join(assigns, ", "),
			spec.name, strings.Join(assigns, ", "))

		rows, err := q.QueryClientDBLast(p.Context, ns, dbName, query, params)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			return nil, fmt.Errorf("create %s: no result", spec.name)
		}
		return rows[0], nil
	}
}

func updateResolver(q Querier, spec tableSpec) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) {
		ownerField, ownerVal, allowed := writeOwner(spec, p.Context)
		if !allowed {
			return nil, errWriteForbidden
		}
		ns, dbName := dbCoords(p.Context)
		idArg, _ := p.Args["id"].(string)
		rid := models.NewRecordID(spec.name, idArg)

		if !spec.versioned {
			assigns, params := buildAssignments(spec, inputArg(p), false)
			if len(assigns) == 0 {
				return getResolver(q, spec)(p) // nothing to change
			}
			params["id"] = rid
			where := "id = $id" + ownerFilter(ownerField, ownerVal, params)
			rows, err := q.QueryClientDB(p.Context, ns, dbName,
				fmt.Sprintf("UPDATE %s SET %s WHERE %s RETURN AFTER",
					quote(spec.name), strings.Join(assigns, ", "), where),
				params,
			)
			if err != nil {
				return nil, err
			}
			if len(rows) == 0 {
				return nil, nil
			}
			return rows[0], nil
		}

		if spec.internal {
			return nil, fmt.Errorf("versioned internal tables are not supported")
		}
		uid := ownerVal

		// Versioned update: append a new version, link ancestry, bump the head.
		assigns, params := buildAssignments(spec, inputArg(p), true)
		params["id"] = rid
		params["uid"] = uid
		params["parents"] = parentVersionIDs(p, spec)
		history := spec.name + "_version"
		setClause := strings.Join(assigns, ",\n\t\t\t\t")
		query := fmt.Sprintf(`
			BEGIN TRANSACTION;
			LET $current = (SELECT * FROM %s WHERE id = $id AND subject_user_id = $uid LIMIT 1)[0];
			LET $new_version = (CREATE %s SET %s = $id, subject_user_id = $uid, %s)[0];
			FOR $parent IN $parents { RELATE $parent->derived_from->$new_version.id; };
			LET $result = (UPDATE $id SET %s, version = $new_version.id WHERE subject_user_id = $uid)[0];
			RETURN [$result];
			COMMIT TRANSACTION;
		`, quote(spec.name), quote(history), quote(spec.name+"_id"), setClause, setClause)

		rows, err := q.QueryClientDBLast(p.Context, ns, dbName, query, params)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			return nil, nil
		}
		return rows[0], nil
	}
}

func deleteResolver(q Querier, spec tableSpec) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) {
		ownerField, ownerVal, allowed := writeOwner(spec, p.Context)
		if !allowed {
			return false, errWriteForbidden
		}
		idArg, _ := p.Args["id"].(string)
		ns, db := dbCoords(p.Context)
		params := map[string]any{"id": models.NewRecordID(spec.name, idArg)}
		where := "id = $id" + ownerFilter(ownerField, ownerVal, params)
		rows, err := q.QueryClientDB(p.Context, ns, db,
			fmt.Sprintf("DELETE %s WHERE %s RETURN BEFORE", quote(spec.name), where),
			params,
		)
		if err != nil {
			return nil, err
		}
		return len(rows) > 0, nil
	}
}

// ── Grant resolvers (shared visibility) ──────────────────────────────────────

// ownsRow reports whether the caller owns the target row — the precondition for
// managing its grants. Returns the record id for reuse.
func ownsRow(q Querier, spec tableSpec, p graphql.ResolveParams) (models.RecordID, bool, error) {
	ownerField, ownerVal, allowed := writeOwner(spec, p.Context)
	if !allowed {
		return models.RecordID{}, false, nil
	}
	idArg, _ := p.Args["id"].(string)
	rid := models.NewRecordID(spec.name, idArg)
	ns, db := dbCoords(p.Context)
	params := map[string]any{"id": rid}
	where := "id = $id" + ownerFilter(ownerField, ownerVal, params)
	rows, err := q.QueryClientDB(p.Context, ns, db,
		fmt.Sprintf("SELECT id FROM %s WHERE %s LIMIT 1", quote(spec.name), where),
		params,
	)
	if err != nil {
		return models.RecordID{}, false, err
	}
	return rid, len(rows) > 0, nil
}

func grantResolver(q Querier, spec tableSpec) graphql.FieldResolveFn {
	grantTable := spec.name + "_grant"
	return func(p graphql.ResolveParams) (any, error) {
		grantee, _ := p.Args["userId"].(string)
		if grantee == "" {
			return false, fmt.Errorf("userId is required")
		}
		rid, owned, err := ownsRow(q, spec, p)
		if err != nil {
			return nil, err
		}
		if !owned {
			return false, errWriteForbidden
		}
		ns, dbName := dbCoords(p.Context)
		params := map[string]any{"id": rid, "grantee": grantee}
		// Idempotent: clear any existing pair, then insert one.
		if _, err := q.QueryClientDB(p.Context, ns, dbName,
			fmt.Sprintf("DELETE %s WHERE row = $id AND grantee_user_id = $grantee", quote(grantTable)), params); err != nil {
			return nil, err
		}
		if _, err := q.QueryClientDB(p.Context, ns, dbName,
			fmt.Sprintf("CREATE %s SET row = $id, grantee_user_id = $grantee", quote(grantTable)), params); err != nil {
			return nil, err
		}
		return true, nil
	}
}

func revokeResolver(q Querier, spec tableSpec) graphql.FieldResolveFn {
	grantTable := spec.name + "_grant"
	return func(p graphql.ResolveParams) (any, error) {
		grantee, _ := p.Args["userId"].(string)
		if grantee == "" {
			return false, fmt.Errorf("userId is required")
		}
		rid, owned, err := ownsRow(q, spec, p)
		if err != nil {
			return nil, err
		}
		if !owned {
			return false, errWriteForbidden
		}
		ns, db := dbCoords(p.Context)
		if _, err := q.QueryClientDB(p.Context, ns, db,
			fmt.Sprintf("DELETE %s WHERE row = $id AND grantee_user_id = $grantee", quote(grantTable)),
			map[string]any{"id": rid, "grantee": grantee}); err != nil {
			return nil, err
		}
		return true, nil
	}
}

// parentVersionIDs reads the parentVersionIds argument into record ids of the
// table's _version table.
func parentVersionIDs(p graphql.ResolveParams, spec tableSpec) []models.RecordID {
	raw, _ := p.Args["parentVersionIds"].([]any)
	out := make([]models.RecordID, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, models.NewRecordID(spec.name+"_version", s))
		}
	}
	return out
}
