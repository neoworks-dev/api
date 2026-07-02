package database

import (
	gql_model "github.com/neoworks/auth/gql/model"
)

// eventFilterEngine wires the shared filter compiler to EventFilter. It reuses
// the same operator logic as contacts (filter_compiler.go); only this field map
// and the and/or/not accessors are event-specific. Note `start` maps to the
// start_time datetime column — the field name and column name differ, which the
// descriptor decouples.
var eventFilterEngine = boolFilter[gql_model.EventFilter]{
	self: eventFieldExprs,
	and:  func(f *gql_model.EventFilter) []*gql_model.EventFilter { return f.And },
	or:   func(f *gql_model.EventFilter) []*gql_model.EventFilter { return f.Or },
	not:  func(f *gql_model.EventFilter) *gql_model.EventFilter { return f.Not },
}

func eventFieldExprs(c *filterCompiler, f *gql_model.EventFilter) []string {
	return []string{
		c.stringExpr("title", f.Title),
		c.stringExpr("description", f.Description),
		c.stringExpr("status", f.Status),
		c.stringExpr("free_busy_status", f.FreeBusyStatus),
		c.stringExpr("privacy", f.Privacy),
		c.stringExpr("time_zone", f.TimeZone),
		c.stringExpr("color", f.Color),
		c.intExpr("priority", f.Priority),
		c.intExpr("sequence", f.Sequence),
		c.stringListExpr("keywords", f.Keywords),
		c.dateExpr("start_time", f.Start),
		c.dateExpr("created_at", f.CreatedAt),
		c.dateExpr("updated_at", f.UpdatedAt),
	}
}
