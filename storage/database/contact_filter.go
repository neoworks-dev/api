package database

import (
	gql_model "github.com/neoworks/auth/gql/model"
)

// contactFilterEngine wires the shared filter compiler to ContactFilter: it maps
// each filter field to its column and operator kind, and exposes the and/or/not
// tree. All operator logic lives in filter_compiler.go and is reused unchanged.
var contactFilterEngine = boolFilter[gql_model.ContactFilter]{
	self: contactFieldExprs,
	and:  func(f *gql_model.ContactFilter) []*gql_model.ContactFilter { return f.And },
	or:   func(f *gql_model.ContactFilter) []*gql_model.ContactFilter { return f.Or },
	not:  func(f *gql_model.ContactFilter) *gql_model.ContactFilter { return f.Not },
}

func contactFieldExprs(c *filterCompiler, f *gql_model.ContactFilter) []string {
	return []string{
		c.stringExpr("formatted_name", f.FormattedName),
		c.stringExpr("kind", f.Kind),
		c.stringExpr("birthday", f.Birthday),
		c.stringExpr("anniversary", f.Anniversary),
		c.stringExpr("title", f.Title),
		c.stringExpr("role", f.Role),
		c.stringExpr("timezone", f.Timezone),
		c.geoExpr("geo", f.Geo),
		c.boolExpr("favorite", f.Favorite),
		c.boolExpr("archived", f.Archived),
		c.boolExpr("deleted", f.Deleted),
		c.dateExpr("created_at", f.CreatedAt),
		c.dateExpr("updated_at", f.UpdatedAt),
		c.fieldListExpr("emails", f.Emails),
		c.fieldListExpr("phones", f.Phones),
		c.fieldListExpr("impps", f.Impps),
		c.fieldListExpr("languages", f.Languages),
		c.fieldListExpr("urls", f.Urls),
		c.stringListExpr("categories", f.Categories),
		c.stringListExpr("nicknames", f.Nicknames),
		c.stringListExpr("notes", f.Notes),
	}
}
