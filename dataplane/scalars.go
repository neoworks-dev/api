package dataplane

import (
	"time"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// jsonScalar carries arbitrary JSON for client fields typed `object`/`any` and
// for nested list elements. Values pass through untouched in both directions;
// the SurrealDB driver marshals maps/slices natively.
var jsonScalar = graphql.NewScalar(graphql.ScalarConfig{
	Name:         "JSON",
	Description:  "Arbitrary JSON value (object/any fields).",
	Serialize:    func(value any) any { return value },
	ParseValue:   func(value any) any { return value },
	ParseLiteral: parseJSONLiteral,
})

func parseJSONLiteral(valueAST ast.Value) any {
	switch v := valueAST.(type) {
	case *ast.StringValue:
		return v.Value
	case *ast.BooleanValue:
		return v.Value
	case *ast.IntValue:
		return v.Value
	case *ast.FloatValue:
		return v.Value
	case *ast.ObjectValue:
		out := make(map[string]any, len(v.Fields))
		for _, f := range v.Fields {
			out[f.Name.Value] = parseJSONLiteral(f.Value)
		}
		return out
	case *ast.ListValue:
		out := make([]any, len(v.Values))
		for i, item := range v.Values {
			out[i] = parseJSONLiteral(item)
		}
		return out
	default:
		return nil
	}
}

// convertValue normalizes a raw SurrealDB-decoded value for the GraphQL layer:
// record ids become their bare identifier (no `table:` prefix) and datetimes
// become RFC3339 strings. Everything else passes through.
func convertValue(raw any) any {
	switch v := raw.(type) {
	case models.RecordID:
		return idString(v)
	case *models.RecordID:
		if v == nil {
			return nil
		}
		return idString(*v)
	case models.CustomDateTime:
		return v.Time.UTC().Format(time.RFC3339Nano)
	case *models.CustomDateTime:
		if v == nil {
			return nil
		}
		return v.Time.UTC().Format(time.RFC3339Nano)
	case time.Time:
		return v.UTC().Format(time.RFC3339Nano)
	default:
		return raw
	}
}
