package database

import (
	gql_model "github.com/neoworks/auth/gql/model"
)

// memoryFilterEngine wires the shared filter compiler (filter_compiler.go) to
// MemoryFilter; only this field map and the and/or/not accessors are specific.
var memoryFilterEngine = boolFilter[gql_model.MemoryFilter]{
	self: memoryFieldExprs,
	and:  func(f *gql_model.MemoryFilter) []*gql_model.MemoryFilter { return f.And },
	or:   func(f *gql_model.MemoryFilter) []*gql_model.MemoryFilter { return f.Or },
	not:  func(f *gql_model.MemoryFilter) *gql_model.MemoryFilter { return f.Not },
}

func memoryFieldExprs(c *filterCompiler, f *gql_model.MemoryFilter) []string {
	return []string{
		c.stringExpr("kind", f.Kind),
		c.stringExpr("title", f.Title),
		c.boolExpr("searchable", f.Searchable),
		c.boolExpr("deleted", f.Deleted),
		c.dateExpr("created_at", f.CreatedAt),
		c.dateExpr("updated_at", f.UpdatedAt),
	}
}
