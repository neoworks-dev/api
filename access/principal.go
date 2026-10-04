// Package access defines who is acting on a request and what the token's
// scopes allow, independent of any stored grant.
package access

import "strings"

const (
	PrincipalTypeUser    = "user"
	PrincipalTypeInstall = "install"
)

// Collections are the node collections a scope can name.
var Collections = []string{"calendar", "contacts", "photos", "files", "google"}

// Principal is the identity a request acts as: the app installation when the
// token carries an install, otherwise the user (the account vault).
type Principal struct {
	UserID    string
	InstallID string
	Scopes    []string
}

func (principal Principal) IsInstall() bool {
	return principal.InstallID != ""
}

func (principal Principal) Type() string {
	if principal.IsInstall() {
		return PrincipalTypeInstall
	}
	return PrincipalTypeUser
}

func (principal Principal) ID() string {
	if principal.IsInstall() {
		return principal.InstallID
	}
	return principal.UserID
}

// CanRead reports whether the token's scopes allow reading the collection.
// A write scope implies read.
func (principal Principal) CanRead(collection string) bool {
	return principal.hasScope(collection, "read") || principal.hasScope(collection, "write")
}

// CanWrite reports whether the token's scopes allow writing the collection, and
// therefore whether a grant's role is capped at admin instead of read.
func (principal Principal) CanWrite(collection string) bool {
	return principal.hasScope(collection, "write")
}

func (principal Principal) ReadableCollections() []string {
	return principal.collectionsWhere(principal.CanRead)
}

func (principal Principal) WritableCollections() []string {
	return principal.collectionsWhere(principal.CanWrite)
}

func (principal Principal) collectionsWhere(allowed func(string) bool) []string {
	collections := []string{}
	for _, collection := range Collections {
		if allowed(collection) {
			collections = append(collections, collection)
		}
	}
	return collections
}

func (principal Principal) hasScope(collection, action string) bool {
	wanted := collection + ":" + action
	for _, scope := range principal.Scopes {
		if strings.TrimSpace(scope) == wanted {
			return true
		}
	}
	return false
}
