package ownership

import (
	"regexp"
	"strings"
)

// A handle names a person or an organization and is its registry scope, so it
// follows the scope rule: lowercase letters, digits and hyphens, 2 to 39
// characters, starting with a letter or digit.
var handlePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,38}$`)

// reservedHandles cannot be claimed by anyone. The seeded Neoworks organization
// holds `neoworks` itself.
var reservedHandles = map[string]bool{
	"openschema": true, "admin": true, "administrator": true, "api": true, "www": true,
	"oauth": true, "vault": true, "auth": true, "login": true, "signup": true,
	"settings": true, "dashboard": true, "developer": true, "developers": true,
	"support": true, "help": true, "security": true, "root": true, "system": true,
	"official": true,
}

const reservedPrefix = "neoworks"

// HandleProblem is why a handle cannot be claimed; empty when it can.
type HandleProblem string

const (
	HandleInvalid  HandleProblem = "invalid"
	HandleReserved HandleProblem = "reserved"
)

// CheckHandle reports why handle cannot be claimed regardless of who holds
// which handles, or "" when its form allows claiming it.
func CheckHandle(handle string) HandleProblem {
	if !handlePattern.MatchString(handle) {
		return HandleInvalid
	}
	if reservedHandles[handle] || strings.HasPrefix(handle, reservedPrefix) {
		return HandleReserved
	}
	return ""
}
