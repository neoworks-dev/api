package database

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	gql_model "github.com/neoworks/auth/gql/model"
	"github.com/neoworks/auth/publicerr"
)

// This is the entity-agnostic filter compiler. It turns the shared per-field
// operator inputs (StringFilter, IntFilter, DateFilter, …) into SurrealQL
// predicates against a caller-supplied column, and provides a generic boolean
// engine (boolFilter[F]) for the and/or/not tree. Each entity wires its concrete
// filter struct to the engine in a small per-entity file (see contact_filter.go,
// event_filter.go); the operator logic below is reused verbatim.
//
// Param names (f0, f1, …) never collide with a list query's own params
// (user/limit/offset/…).

// durationPattern matches a SurrealDB duration literal (e.g. 30d, 12h, 1w2d).
// withinLast values are inlined into the query, so they must be validated.
var durationPattern = regexp.MustCompile(`^(\d+(ns|µs|us|ms|s|m|h|d|w|y))+$`)

const maxFilterDepth = 8

type filterCompiler struct {
	params map[string]any
	n      int
	depth  int
	err    error
	// ftsColumns names the columns backed by a FULLTEXT index, so StringFilter.search
	// (the @@ operator) can be rejected up front on any other column instead of
	// failing opaquely inside SurrealDB. Empty for entities with no FTS index.
	ftsColumns map[string]bool
}

func newFilterCompiler() *filterCompiler {
	return &filterCompiler{params: map[string]any{}}
}

// ftsHint lists the searchable columns for the current entity, for error messages.
func (c *filterCompiler) ftsHint() string {
	if len(c.ftsColumns) == 0 {
		return "no fields on this entity support search"
	}
	cols := make([]string, 0, len(c.ftsColumns))
	for col := range c.ftsColumns {
		cols = append(cols, col)
	}
	sort.Strings(cols)
	return "searchable fields: " + strings.Join(cols, ", ")
}

// bind registers a value under a fresh param name and returns the "$name" ref.
func (c *filterCompiler) bind(value any) string {
	name := fmt.Sprintf("f%d", c.n)
	c.n++
	c.params[name] = value
	return "$" + name
}

// boolFilter is the generic boolean engine for a concrete filter type F. An
// entity supplies `self` (the node's own field predicates) and the and/or/not
// accessors; the depth cap and tree recursion are handled here, so a new entity
// only describes its fields.
type boolFilter[F any] struct {
	self func(c *filterCompiler, f *F) []string
	and  func(f *F) []*F
	or   func(f *F) []*F
	not  func(f *F) *F
}

// compile returns the WHERE expression for a filter node, or "" when it adds
// nothing.
func (b boolFilter[F]) compile(c *filterCompiler, f *F) string {
	if f == nil || c.err != nil {
		return ""
	}
	c.depth++
	defer func() { c.depth-- }()
	if c.depth > maxFilterDepth {
		c.err = publicerr.New(fmt.Sprintf("filter nested too deeply (max %d)", maxFilterDepth))
		return ""
	}

	var parts []string
	add := func(expr string) {
		if expr != "" {
			parts = append(parts, expr)
		}
	}

	for _, expr := range b.self(c, f) {
		add(expr)
	}
	add(b.group(c, b.and(f), " AND "))
	add(b.group(c, b.or(f), " OR "))
	if n := b.not(f); n != nil {
		if inner := b.compile(c, n); inner != "" {
			add("!(" + inner + ")")
		}
	}

	if len(parts) == 0 {
		return ""
	}
	return "(" + strings.Join(parts, " AND ") + ")"
}

// group compiles a list of sub-filters joined by AND or OR.
func (b boolFilter[F]) group(c *filterCompiler, filters []*F, joiner string) string {
	if len(filters) == 0 {
		return ""
	}
	var sub []string
	for _, f := range filters {
		if expr := b.compile(c, f); expr != "" {
			sub = append(sub, expr)
		}
	}
	if len(sub) == 0 {
		return ""
	}
	return "(" + strings.Join(sub, joiner) + ")"
}

// ── Per-operator expressions (entity-agnostic; `col` is any field expression) ──

// stringExpr builds the predicate for a scalar string column. `col` is the field
// expression the operators apply to (e.g. "formatted_name", or "value" inside an
// element filter). Multiple operators on one filter are ANDed.
func (c *filterCompiler) stringExpr(col string, f *gql_model.StringFilter) string {
	if f == nil {
		return ""
	}
	lower := "string::lowercase(" + col + ")"
	var parts []string
	if f.Eq != nil {
		parts = append(parts, col+" = "+c.bind(*f.Eq))
	}
	if f.Ne != nil {
		parts = append(parts, col+" != "+c.bind(*f.Ne))
	}
	if f.Contains != nil {
		parts = append(parts, lower+" CONTAINS "+c.bind(strings.ToLower(*f.Contains)))
	}
	if f.StartsWith != nil {
		parts = append(parts, "string::starts_with("+lower+", "+c.bind(strings.ToLower(*f.StartsWith))+")")
	}
	if f.EndsWith != nil {
		parts = append(parts, "string::ends_with("+lower+", "+c.bind(strings.ToLower(*f.EndsWith))+")")
	}
	if f.Matches != nil {
		parts = append(parts, "string::matches("+col+", "+c.bind(*f.Matches)+")")
	}
	if f.Search != nil {
		// Full-text @@ match requires a FULLTEXT index on the column. Reject up front
		// on unindexed columns so the caller gets a precise reason rather than an
		// opaque SurrealDB failure.
		if !c.ftsColumns[col] {
			c.err = publicerr.New(fmt.Sprintf("search requires a FULLTEXT index on %q; %s", col, c.ftsHint()))
			return ""
		}
		parts = append(parts, col+" @@ "+c.bind(*f.Search))
	}
	if f.Fuzzy != nil {
		parts = append(parts, "string::similarity::fuzzy("+col+", "+c.bind(*f.Fuzzy)+") > 0")
	}
	if f.In != nil {
		parts = append(parts, col+" IN "+c.bind(f.In))
	}
	if f.IsNull != nil {
		if *f.IsNull {
			parts = append(parts, col+" = NONE")
		} else {
			parts = append(parts, col+" != NONE")
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " AND ")
}

func (c *filterCompiler) boolExpr(col string, f *gql_model.BoolFilter) string {
	if f == nil || f.Eq == nil {
		return ""
	}
	return col + " = " + c.bind(*f.Eq)
}

func (c *filterCompiler) intExpr(col string, f *gql_model.IntFilter) string {
	if f == nil {
		return ""
	}
	var parts []string
	if f.Eq != nil {
		parts = append(parts, col+" = "+c.bind(*f.Eq))
	}
	if f.Gt != nil {
		parts = append(parts, col+" > "+c.bind(*f.Gt))
	}
	if f.Lt != nil {
		parts = append(parts, col+" < "+c.bind(*f.Lt))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " AND ")
}

// dateExpr builds predicates for a real datetime column. ISO-8601 instants are
// bound and cast with <datetime>; withinLast is a validated duration literal
// (durations can't be bound as params, so the token is inlined after a format check).
func (c *filterCompiler) dateExpr(col string, f *gql_model.DateFilter) string {
	if f == nil {
		return ""
	}
	var parts []string
	if f.Eq != nil {
		parts = append(parts, col+" = <datetime>"+c.bind(*f.Eq))
	}
	if f.Before != nil {
		parts = append(parts, col+" < <datetime>"+c.bind(*f.Before))
	}
	if f.After != nil {
		parts = append(parts, col+" > <datetime>"+c.bind(*f.After))
	}
	if f.WithinLast != nil {
		if !durationPattern.MatchString(*f.WithinLast) {
			c.err = publicerr.New(fmt.Sprintf("invalid duration %q for withinLast (e.g. 30d, 12h, 1w2d)", *f.WithinLast))
			return ""
		}
		parts = append(parts, col+" > time::now() - "+*f.WithinLast)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " AND ")
}

// stringListExpr filters a list of plain strings (categories/nicknames/keywords).
// Absent lists are NONE not [], so coalesce before the array operators.
func (c *filterCompiler) stringListExpr(col string, f *gql_model.StringListFilter) string {
	if f == nil {
		return ""
	}
	list := "(" + col + " ?? [])"
	var parts []string
	if f.HasAll != nil {
		parts = append(parts, list+" CONTAINSALL "+c.bind(f.HasAll))
	}
	if f.HasAny != nil {
		parts = append(parts, list+" CONTAINSANY "+c.bind(f.HasAny))
	}
	if f.Contains != nil {
		// $this is the element value inside a string-array WHERE filter.
		parts = append(parts, "array::len("+list+"[WHERE string::lowercase($this) CONTAINS "+c.bind(strings.ToLower(*f.Contains))+"]) > 0")
	}
	if f.IsEmpty != nil {
		if *f.IsEmpty {
			parts = append(parts, "array::len("+list+") = 0")
		} else {
			parts = append(parts, "array::len("+list+") > 0")
		}
	}
	if f.Size != nil {
		parts = append(parts, c.intExpr("array::len("+list+")", f.Size))
	}
	parts = nonEmpty(parts)
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " AND ")
}

// geoExpr filters a GEO point stored as {lat, lng}. The point is constructed
// inline with type::point([lng, lat]) — GeoJSON order is (lng, lat). A guard on
// <col>.lat excludes rows without a point from near/within.
func (c *filterCompiler) geoExpr(col string, f *gql_model.GeoFilter) string {
	if f == nil {
		return ""
	}
	point := "type::point([" + col + ".lng, " + col + ".lat])"
	present := col + ".lat != NONE"
	var parts []string
	if f.Near != nil {
		lng := c.bind(f.Near.Lng)
		lat := c.bind(f.Near.Lat)
		radius := c.bind(f.Near.RadiusMeters)
		parts = append(parts, "("+present+" AND geo::distance("+point+", type::point(["+lng+", "+lat+"])) <= "+radius+")")
	}
	if f.Within != nil {
		// Bound params don't coerce to geometry in SurrealDB 3.0; the GeoJSON must
		// be an inline literal. renderGeoJSON validates every leaf is a string or
		// number, so nothing untrusted reaches the query.
		geojson, err := renderGeoJSON(f.Within, 0)
		if err != nil {
			c.err = publicerr.New("invalid geo within: " + err.Error())
			return ""
		}
		parts = append(parts, "("+present+" AND "+point+" INSIDE "+geojson+")")
	}
	if f.IsNull != nil {
		if *f.IsNull {
			parts = append(parts, col+" = NONE")
		} else {
			parts = append(parts, col+" != NONE")
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " AND ")
}

const maxGeoJSONDepth = 8

// renderGeoJSON turns a decoded GeoJSON value into a SurrealQL geometry literal.
// Only objects, arrays, strings and numbers are allowed; any other leaf (or
// excessive nesting) is rejected so the inlined literal can never carry an
// injection. Object keys are quoted; strings are escaped.
func renderGeoJSON(value any, depth int) (string, error) {
	if depth > maxGeoJSONDepth {
		return "", fmt.Errorf("geo within nested too deeply (max %d)", maxGeoJSONDepth)
	}
	switch v := value.(type) {
	case map[string]any:
		parts := make([]string, 0, len(v))
		for key, val := range v {
			rendered, err := renderGeoJSON(val, depth+1)
			if err != nil {
				return "", err
			}
			parts = append(parts, quoteGeoString(key)+": "+rendered)
		}
		return "{ " + strings.Join(parts, ", ") + " }", nil
	case []any:
		parts := make([]string, 0, len(v))
		for _, val := range v {
			rendered, err := renderGeoJSON(val, depth+1)
			if err != nil {
				return "", err
			}
			parts = append(parts, rendered)
		}
		return "[" + strings.Join(parts, ", ") + "]", nil
	case string:
		return quoteGeoString(v), nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	case int:
		return strconv.Itoa(v), nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case json.Number:
		// json.Number is already a numeric literal; reject anything non-numeric.
		if _, err := v.Float64(); err != nil {
			return "", fmt.Errorf("invalid number in geo within: %q", v.String())
		}
		return v.String(), nil
	default:
		return "", fmt.Errorf("unsupported value in geo within: %T", value)
	}
}

// quoteGeoString single-quotes a string for SurrealQL, escaping backslashes and
// quotes.
func quoteGeoString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return "'" + s + "'"
}

func nonEmpty(in []string) []string {
	out := in[:0]
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
