package gql

import (
	"fmt"
	"strings"

	"github.com/neoworks/auth/oauth"
)

// claimHasScope reports whether the token carries an exact scope string.
func claimHasScope(claim *oauth.Claims, scope string) bool {
	if claim == nil {
		return false
	}
	for _, s := range claim.Scope {
		if s == scope {
			return true
		}
	}
	return false
}

// parsedScope is the decomposed form of a `organization?:entity:action` scope.
// OrgSlug is empty when the scope targets the user's personal data on Neoworks.
type parsedScope struct {
	OrgSlug string
	Entity  string
	Action  string
}

// parseScope validates and splits a scope string of the form
// `organization?:entity:action`. The organization segment is optional.
func parseScope(raw string) (parsedScope, error) {
	parts := strings.Split(strings.TrimSpace(raw), ":")
	var p parsedScope

	switch len(parts) {
	case 2:
		p.Entity, p.Action = parts[0], parts[1]
	case 3:
		p.OrgSlug, p.Entity, p.Action = parts[0], parts[1], parts[2]
	default:
		return p, fmt.Errorf("invalid scope %q: expected entity:action or organization:entity:action", raw)
	}

	if p.Entity == "" {
		return p, fmt.Errorf("invalid scope %q: empty entity", raw)
	}
	if p.Action != "read" && p.Action != "write" {
		return p, fmt.Errorf("invalid scope %q: action must be read or write", raw)
	}
	return p, nil
}
