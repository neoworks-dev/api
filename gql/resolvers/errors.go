package gql

import "errors"

// PublicError wraps a message that is safe to expose to API clients. Errors that
// are not PublicError are scrubbed to a generic message by the GraphQL error
// presenter, so internal details (DB schema, record ids, driver text) never
// leak to callers.
type PublicError struct{ msg string }

func (e PublicError) Error() string { return e.msg }

// Public marks a message as safe to return to the client.
func Public(msg string) error { return PublicError{msg: msg} }

// AsPublic returns the public message if err (or anything in its chain) is a
// PublicError.
func AsPublic(err error) (string, bool) {
	var pub PublicError
	if errors.As(err, &pub) {
		return pub.msg, true
	}
	return "", false
}
