// Package access defines who is acting on a request and what the token's
// scopes allow, independent of any stored grant.
package access

import (
	"regexp"
	"strings"
)

const (
	PrincipalTypeUser    = "user"
	PrincipalTypeInstall = "install"
)

var collectionSegmentPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ParseCollection splits a collection, the registry path `@scope/name` of the
// schema its nodes follow, into scope and name.
func ParseCollection(collection string) (scope, name string, ok bool) {
	path, hasAt := strings.CutPrefix(collection, "@")
	if !hasAt {
		return "", "", false
	}
	scope, name, hasSlash := strings.Cut(path, "/")
	if !hasSlash || !collectionSegmentPattern.MatchString(scope) || !collectionSegmentPattern.MatchString(name) {
		return "", "", false
	}
	return scope, name, true
}

func IsValidCollection(collection string) bool {
	_, _, ok := ParseCollection(collection)
	return ok
}

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
// therefore whether a grant's role is capped at read.
func (principal Principal) CanWrite(collection string) bool {
	return principal.hasScope(collection, "write")
}

// CanShare reports whether the token's scopes allow sharing the collection with
// other people.
func (principal Principal) CanShare(collection string) bool {
	return principal.hasScope(collection, "share")
}

func (principal Principal) ReadableCollections() []string {
	return principal.collectionsWhere(principal.CanRead)
}

func (principal Principal) WritableCollections() []string {
	return principal.collectionsWhere(principal.CanWrite)
}

// collectionsWhere lists the collections the token's scopes name, once each,
// that pass allowed.
func (principal Principal) collectionsWhere(allowed func(string) bool) []string {
	collections := []string{}
	for _, scope := range principal.Scopes {
		collection := scopeCollection(scope)
		if collection == "" || containsCollection(collections, collection) || !allowed(collection) {
			continue
		}
		collections = append(collections, collection)
	}
	return collections
}

// scopeCollection is the collection a `<collection>:<action>` scope names, or
// empty for any other scope.
func scopeCollection(scope string) string {
	trimmed := strings.TrimSpace(scope)
	separator := strings.LastIndex(trimmed, ":")
	if separator < 0 {
		return ""
	}
	collection := trimmed[:separator]
	if !IsValidCollection(collection) {
		return ""
	}
	return collection
}

func containsCollection(collections []string, wanted string) bool {
	for _, collection := range collections {
		if collection == wanted {
			return true
		}
	}
	return false
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
