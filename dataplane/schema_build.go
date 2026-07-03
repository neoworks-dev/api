package dataplane

import (
	"fmt"

	"github.com/graphql-go/graphql"
)

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[0] >= 'a' && b[0] <= 'z' {
		b[0] -= 32
	}
	return string(b)
}

// buildSchema assembles a runtime GraphQL schema exposing CRUD for each data
// table. subject_user_id and version are never added to any type or input.
func buildSchema(q Querier, specs []tableSpec) (graphql.Schema, error) {
	queryFields := graphql.Fields{}
	mutationFields := graphql.Fields{}
	usedTypeNames := map[string]bool{}

	claim := func(name string) error {
		if usedTypeNames[name] {
			return fmt.Errorf("generated type name collision: %q", name)
		}
		usedTypeNames[name] = true
		return nil
	}

	for _, spec := range specs {
		for _, n := range []string{spec.name, spec.name + "CreateInput", spec.name + "UpdateInput", spec.name + "FilterInput"} {
			if err := claim(n); err != nil {
				return graphql.Schema{}, err
			}
		}

		objType := buildObjectType(spec)
		createInput := buildInputObject(spec.name+"CreateInput", spec, true)
		updateInput := buildInputObject(spec.name+"UpdateInput", spec, false)
		filterInput := buildFilterInput(spec)

		// Queries: get + list (+ history for versioned).
		queryFields[spec.name] = &graphql.Field{
			Type:    objType,
			Args:    graphql.FieldConfigArgument{"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.ID)}},
			Resolve: getResolver(q, spec),
		}
		listArgs := graphql.FieldConfigArgument{
			"limit":  &graphql.ArgumentConfig{Type: graphql.Int},
			"offset": &graphql.ArgumentConfig{Type: graphql.Int},
		}
		if filterInput != nil {
			listArgs["filter"] = &graphql.ArgumentConfig{Type: filterInput}
		}
		// Tables with a fulltext index gain a BM25 `search` argument that ranks rows
		// by relevance across the indexed string fields.
		if len(spec.searchFields) > 0 {
			listArgs["search"] = &graphql.ArgumentConfig{Type: graphql.String}
		}
		queryFields[spec.name+"s"] = &graphql.Field{
			Type:    graphql.NewList(objType),
			Args:    listArgs,
			Resolve: listResolver(q, spec),
		}

		// Mutations. create accepts an optional client-supplied id so callers can
		// use their own stable ids as the record id (idempotent creates).
		mutationFields["create"+upperFirst(spec.name)] = &graphql.Field{
			Type: objType,
			Args: graphql.FieldConfigArgument{
				"id":    &graphql.ArgumentConfig{Type: graphql.ID},
				"input": &graphql.ArgumentConfig{Type: graphql.NewNonNull(createInput)},
			},
			Resolve: createResolver(q, spec),
		}
		updateArgs := graphql.FieldConfigArgument{
			"id":    &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.ID)},
			"input": &graphql.ArgumentConfig{Type: graphql.NewNonNull(updateInput)},
		}
		if spec.versioned {
			updateArgs["parentVersionIds"] = &graphql.ArgumentConfig{Type: graphql.NewList(graphql.NewNonNull(graphql.ID))}
		}
		mutationFields["update"+upperFirst(spec.name)] = &graphql.Field{
			Type:    objType,
			Args:    updateArgs,
			Resolve: updateResolver(q, spec),
		}
		mutationFields["delete"+upperFirst(spec.name)] = &graphql.Field{
			Type:    graphql.Boolean,
			Args:    graphql.FieldConfigArgument{"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.ID)}},
			Resolve: deleteResolver(q, spec),
		}

		// Shared tables expose owner-managed read grants to specific users.
		if spec.sharedRead() {
			grantArgs := graphql.FieldConfigArgument{
				"id":     &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.ID)},
				"userId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			}
			mutationFields["grant"+upperFirst(spec.name)] = &graphql.Field{
				Type: graphql.Boolean, Args: grantArgs, Resolve: grantResolver(q, spec),
			}
			mutationFields["revoke"+upperFirst(spec.name)] = &graphql.Field{
				Type: graphql.Boolean, Args: grantArgs, Resolve: revokeResolver(q, spec),
			}
		}

		if spec.versioned {
			queryFields[spec.name+"History"] = &graphql.Field{
				Type:    graphql.NewList(objType),
				Args:    graphql.FieldConfigArgument{"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.ID)}},
				Resolve: historyResolver(q, spec),
			}
		}
	}

	if len(queryFields) == 0 {
		queryFields["_ping"] = &graphql.Field{
			Type:    graphql.Boolean,
			Resolve: func(graphql.ResolveParams) (any, error) { return true, nil },
		}
	}

	cfg := graphql.SchemaConfig{
		Query: graphql.NewObject(graphql.ObjectConfig{Name: "Query", Fields: queryFields}),
	}
	if len(mutationFields) > 0 {
		cfg.Mutation = graphql.NewObject(graphql.ObjectConfig{Name: "Mutation", Fields: mutationFields})
	}
	return graphql.NewSchema(cfg)
}

func buildObjectType(spec tableSpec) *graphql.Object {
	fields := graphql.Fields{
		"id": &graphql.Field{Type: graphql.NewNonNull(graphql.ID), Resolve: fieldResolver("id")},
	}
	for _, f := range spec.fields {
		fields[f.name] = &graphql.Field{Type: graphQLType(f.typ), Resolve: fieldResolver(f.name)}
	}
	if spec.versioned || spec.needsTimestamps() {
		fields["created_at"] = &graphql.Field{Type: graphql.String, Resolve: fieldResolver("created_at")}
		fields["updated_at"] = &graphql.Field{Type: graphql.String, Resolve: fieldResolver("updated_at")}
	}
	return graphql.NewObject(graphql.ObjectConfig{Name: spec.name, Fields: fields})
}

// buildInputObject builds a create or update input. For create, fields without an
// `option<>` wrapper are required; for update, every field is optional.
func buildInputObject(name string, spec tableSpec, requireMandatory bool) *graphql.InputObject {
	fields := graphql.InputObjectConfigFieldMap{}
	for _, f := range spec.fields {
		t := graphQLType(f.typ)
		_, optional := unwrapOption(f.typ)
		if requireMandatory && !optional {
			t = graphql.NewNonNull(t)
		}
		fields[f.name] = &graphql.InputObjectFieldConfig{Type: t}
	}
	return graphql.NewInputObject(graphql.InputObjectConfig{Name: name, Fields: fields})
}

// buildFilterInput builds an equality filter over scalar fields, or nil if none.
func buildFilterInput(spec tableSpec) *graphql.InputObject {
	fields := graphql.InputObjectConfigFieldMap{}
	for _, f := range spec.fields {
		if !isScalarFilterable(f.typ) {
			continue
		}
		fields[f.name] = &graphql.InputObjectFieldConfig{Type: graphQLType(f.typ)}
	}
	if len(fields) == 0 {
		return nil
	}
	return graphql.NewInputObject(graphql.InputObjectConfig{Name: spec.name + "FilterInput", Fields: fields})
}
