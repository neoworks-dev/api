package database

import (
	gql_model "github.com/neoworks/auth/gql/model"
)

// fileFilterEngine wires the shared filter compiler to FileFilter. All operator
// logic lives in filter_compiler.go and is reused unchanged (see contact_filter.go).
var fileFilterEngine = boolFilter[gql_model.FileFilter]{
	self: fileFieldExprs,
	and:  func(f *gql_model.FileFilter) []*gql_model.FileFilter { return f.And },
	or:   func(f *gql_model.FileFilter) []*gql_model.FileFilter { return f.Or },
	not:  func(f *gql_model.FileFilter) *gql_model.FileFilter { return f.Not },
}

func fileFieldExprs(c *filterCompiler, f *gql_model.FileFilter) []string {
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
