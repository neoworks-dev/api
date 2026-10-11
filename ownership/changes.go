package ownership

// ChangeProblem is why a change to a member's grants is refused; empty when it
// is allowed.
type ChangeProblem string

const (
	ProblemMissingPermission ChangeProblem = "missing_permission"
	ProblemEscalation        ChangeProblem = "escalation"
	ProblemLastManager       ChangeProblem = "last_members_manager"
	ProblemInvalidGrant      ChangeProblem = "invalid_grant"
)

// GrantChange replaces one member's grants. Actor holds ActorGrants; Before and
// After are the member's grants; Members maps every member to their grants
// before the change.
type GrantChange struct {
	ActorGrants []Grant
	Before      []Grant
	After       []Grant
	MemberID    string
	Members     map[string][]Grant
}

// CheckGrantChange applies the member rules: the actor needs members.manage,
// may only add or remove grants it holds at the same or a wider reach, and the
// organization keeps at least one member with members.manage.
func CheckGrantChange(change GrantChange) ChangeProblem {
	if !allValid(change.After) {
		return ProblemInvalidGrant
	}
	if !Allows(change.ActorGrants, MembersManage, "") {
		return ProblemMissingPermission
	}
	if !coversAll(change.ActorGrants, added(change.Before, change.After)) {
		return ProblemEscalation
	}
	if !coversAll(change.ActorGrants, added(change.After, change.Before)) {
		return ProblemEscalation
	}
	if !keepsManager(change.Members, change.MemberID, change.After) {
		return ProblemLastManager
	}
	return ""
}

// CheckGrantsToInvite applies the same reach rule to the grants an invitation
// offers.
func CheckGrantsToInvite(actorGrants []Grant, offered []Grant) ChangeProblem {
	if !allValid(offered) {
		return ProblemInvalidGrant
	}
	if !Allows(actorGrants, MembersManage, "") {
		return ProblemMissingPermission
	}
	if !coversAll(actorGrants, offered) {
		return ProblemEscalation
	}
	return ""
}

// CheckLeave reports whether the member may leave or be removed without leaving
// the organization without members.manage.
func CheckLeave(members map[string][]Grant, memberID string) ChangeProblem {
	if !keepsManager(members, memberID, nil) {
		return ProblemLastManager
	}
	return ""
}

func allValid(grants []Grant) bool {
	for _, grant := range grants {
		if !grant.IsValid() {
			return false
		}
	}
	return true
}

// added lists the grants in after that before does not already cover.
func added(before []Grant, after []Grant) []Grant {
	result := []Grant{}
	for _, grant := range after {
		if !coveredBy(before, grant) {
			result = append(result, grant)
		}
	}
	return result
}

func coversAll(held []Grant, wanted []Grant) bool {
	for _, grant := range wanted {
		if !coveredBy(held, grant) {
			return false
		}
	}
	return true
}

// keepsManager reports whether someone still holds members.manage once memberID
// holds after instead of their current grants.
func keepsManager(members map[string][]Grant, memberID string, after []Grant) bool {
	if Allows(after, MembersManage, "") {
		return true
	}
	for otherID, grants := range members {
		if otherID != memberID && Allows(grants, MembersManage, "") {
			return true
		}
	}
	return false
}
