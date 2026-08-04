package gql

import "github.com/neoworks/auth/publicerr"

// PublicError is retained as an alias so existing references keep working; the
// canonical definition now lives in the shared publicerr package (importable by
// the storage layer without an import cycle).
type PublicError = publicerr.Error

// Public marks a message as safe to return to the client.
func Public(msg string) error { return publicerr.New(msg) }

// AsPublic returns the public message if err (or anything in its chain) is a
// PublicError.
func AsPublic(err error) (string, bool) { return publicerr.Message(err) }
