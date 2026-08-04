// Package publicerr holds the "safe to expose to API clients" error type. It
// lives below both the storage and gql packages so either can produce a
// client-safe error without creating an import cycle. Errors that are NOT a
// publicerr are scrubbed to a generic message by the GraphQL error presenter, so
// internal details (DB schema, record ids, driver text) never leak.
package publicerr

import (
	"errors"
	"strings"
)

// Error wraps a message that is safe to return to API clients.
type Error struct{ msg string }

func (e Error) Error() string { return e.msg }

// New marks a message as safe to return to the client.
func New(msg string) error { return Error{msg: msg} }

// Message returns the client-safe message if err (or anything in its chain) is a
// publicerr.Error.
func Message(err error) (string, bool) {
	var pub Error
	if errors.As(err, &pub) {
		return pub.msg, true
	}
	return "", false
}

// dbErrorSignatures maps a lowercased substring of a raw SurrealDB error to a
// sanitized, data-free client message. This is an explicit allowlist: a raw driver
// error is only surfaced when it matches a known query-shape failure class. Order
// matters — the first matching signature wins, so keep the more specific ones
// first. Anything unmatched stays scrubbed to the generic message by the caller.
var dbErrorSignatures = []struct {
	needle  string
	message string
}{
	{"fulltext", "this query needs a FULLTEXT index that does not exist"},
	{"search index", "this query needs a search index that does not exist"},
	{"no index", "this query needs an index that does not exist"},
	{"index not found", "this query needs an index that does not exist"},
	{"regular expression", "a filter contains an invalid regular expression"},
	{"invalid regex", "a filter contains an invalid regular expression"},
	{"expected a datetime", "a date filter value is not a valid datetime"},
	{"convert to a datetime", "a date filter value is not a valid datetime"},
	{"cannot perform", "a filter value has the wrong type for this field"},
	{"incorrect arguments", "a filter value has the wrong type for this field"},
}

// ClassifyDBError maps a raw database error to a sanitized public message when it
// matches a known query-shape failure. Returns ok=false for anything unrecognized
// so the caller keeps default-deny (generic "Internal server error"). It never
// echoes the raw driver text, which can contain record ids or field values.
func ClassifyDBError(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	lower := strings.ToLower(err.Error())
	for _, sig := range dbErrorSignatures {
		if strings.Contains(lower, sig.needle) {
			return sig.message, true
		}
	}
	return "", false
}
