package database

import (
	gql_model "github.com/neoworks/auth/gql/model"
)

// mediaFilterEngine wires the shared filter compiler to MediaFilter. All operator
// logic lives in filter_compiler.go and is reused unchanged (see contact_filter.go).
var mediaFilterEngine = boolFilter[gql_model.MediaFilter]{
	self: mediaFieldExprs,
	and:  func(f *gql_model.MediaFilter) []*gql_model.MediaFilter { return f.And },
	or:   func(f *gql_model.MediaFilter) []*gql_model.MediaFilter { return f.Or },
	not:  func(f *gql_model.MediaFilter) *gql_model.MediaFilter { return f.Not },
}

func mediaFieldExprs(c *filterCompiler, f *gql_model.MediaFilter) []string {
	return []string{
		c.stringExpr("filename", f.Filename),
		c.stringExpr("mime_type", f.MimeType),
		c.intExpr("size", f.Size),
		c.dateExpr("created_at", f.CreatedAt),
		c.dateExpr("updated_at", f.UpdatedAt),
		c.dateExpr("capture_date", f.CaptureDate),
		c.geoExpr("location", f.Location),
	}
}
