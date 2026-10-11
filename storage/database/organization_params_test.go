package database

import (
	"testing"

	"github.com/google/uuid"
	"github.com/neoworks/auth/ownership"
)

func TestOrganizationStatementsBindEveryParameter(t *testing.T) {
	userID := uuid.NewString()
	requireAllBound(t, "claim handle", claimUserHandleStatement, claimUserHandleParams(userID, "acme"))
	requireAllBound(t, "create organization", createOrganizationStatement, createOrganizationParams(userID, "acme", "Acme"))
	requireAllBound(t, "audit", recordAuditWithActorStatement, recordAuditParams(AuditInput{Organization: "acme", ActorID: userID, Action: "a"}))
	requireAllBound(t, "system audit", recordAuditStatement, recordAuditParams(AuditInput{Organization: "acme", Action: "a"}))

	grants := []ownership.Grant{ownership.ForApp(ownership.AppsEdit, "songs")}
	byEmail := InvitationInput{Email: "a@example.com", Grants: grants}
	requireAllBound(t, "invite by email", invitationStatement(byEmail), invitationParams("acme", userID, byEmail, "", uuid.NewString()))
	byCode := InvitationInput{ContactCode: "ABCDEFGHJKMN", Grants: grants}
	requireAllBound(t, "invite by code", invitationStatement(byCode), invitationParams("acme", userID, byCode, uuid.NewString(), uuid.NewString()))
}
