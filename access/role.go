package access

const (
	RoleRead  = "read"
	RoleWrite = "write"
)

var roleRank = map[string]int{
	RoleRead:  1,
	RoleWrite: 2,
}

func ValidRole(role string) bool {
	_, known := roleRank[role]
	return known
}

// RoleAtLeast reports whether role grants everything minimum does.
func RoleAtLeast(role, minimum string) bool {
	return roleRank[role] >= roleRank[minimum] && roleRank[role] > 0
}

// LowerRole returns whichever of the two roles grants less.
func LowerRole(role, other string) string {
	if RoleAtLeast(role, other) {
		return other
	}
	return role
}

// RolesAtLeast lists the stored roles that satisfy minimum.
func RolesAtLeast(minimum string) []string {
	roles := []string{}
	for _, role := range []string{RoleRead, RoleWrite} {
		if RoleAtLeast(role, minimum) {
			roles = append(roles, role)
		}
	}
	return roles
}

// RolesUsable lists the stored roles that satisfy minimum once the token's
// scopes cap them: a read scope caps every grant at read, a write scope leaves
// the grant's own role in force.
func (principal Principal) RolesUsable(collection, minimum string) []string {
	if !principal.CanRead(collection) {
		return []string{}
	}
	if minimum != RoleRead && !principal.CanWrite(collection) {
		return []string{}
	}
	return RolesAtLeast(minimum)
}
