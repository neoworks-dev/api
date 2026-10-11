package organizations

import (
	"errors"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/ownership"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/utils"
)

func (h *Handler) listInvitations(w http.ResponseWriter, r *http.Request) {
	acting, ok := h.permitted(w, r, ownership.MembersManage)
	if !ok {
		return
	}
	invitations, err := h.store.ListInvitations(r.Context(), acting.handle)
	if err != nil {
		writeStoreError(w, "listInvitations", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"invitations": invitations})
}

type invitationRequest struct {
	Email       string            `json:"email"`
	ContactCode string            `json:"contactCode"`
	Grants      []ownership.Grant `json:"grants"`
}

func (h *Handler) createInvitation(w http.ResponseWriter, r *http.Request) {
	acting, ok := h.writable(w, r, ownership.MembersManage)
	if !ok {
		return
	}
	var request invitationRequest
	if !respond.Decode(w, r, &request, maxRequestBody) {
		return
	}
	input, ok := invitationInput(w, request)
	if !ok || !h.appsExist(w, r, acting.handle, input.Grants) {
		return
	}
	if problem := ownership.CheckGrantsToInvite(acting.grants, input.Grants); problem != "" {
		writeChangeProblem(w, problem)
		return
	}
	invitation, err := h.store.CreateInvitation(r.Context(), acting.handle, acting.userID, input)
	if err != nil {
		writeInvitationError(w, err)
		return
	}
	h.auditInvitation(r, acting, database.AuditInvitationCreated, invitation.ID, invitationLabel(input))
	respond.JSON(w, http.StatusCreated, invitation)
}

// invitationInput validates the address: exactly one of email and contact code.
func invitationInput(w http.ResponseWriter, request invitationRequest) (database.InvitationInput, bool) {
	email := strings.TrimSpace(request.Email)
	contactCode, validCode := utils.NormalizeContactCode(request.ContactCode)
	grants := ownership.Normalize(request.Grants)
	if email != "" && request.ContactCode == "" && isEmail(email) {
		return database.InvitationInput{Email: email, Grants: grants}, true
	}
	if email == "" && request.ContactCode != "" && validCode {
		return database.InvitationInput{ContactCode: contactCode, Grants: grants}, true
	}
	respond.JSON(w, http.StatusBadRequest, map[string]string{
		"error": "invalid_invitee", "field": "email", "message": "give either a valid email address or a contact code",
	})
	return database.InvitationInput{}, false
}

func isEmail(address string) bool {
	parsed, err := mail.ParseAddress(address)
	return err == nil && parsed.Address == address
}

func writeInvitationError(w http.ResponseWriter, err error) {
	if errors.Is(err, database.ErrUnknownPrincipal) {
		respond.JSON(w, http.StatusBadRequest, map[string]string{
			"error": "unknown_contact_code", "field": "contactCode", "message": "no account has that contact code",
		})
		return
	}
	writeStoreError(w, "createInvitation", err)
}

func invitationLabel(input database.InvitationInput) string {
	if input.ContactCode != "" {
		return input.ContactCode
	}
	return strings.ToLower(input.Email)
}

func (h *Handler) auditInvitation(r *http.Request, acting *organizationContext, action string, invitationID string, label string) {
	h.audit(r, database.AuditInput{
		Organization: acting.handle, ActorID: acting.userID, Action: action,
		Target: database.AuditTarget{Kind: "invitation", ID: invitationID, Label: label},
	})
}

func (h *Handler) revokeInvitation(w http.ResponseWriter, r *http.Request) {
	acting, ok := h.writable(w, r, ownership.MembersManage)
	if !ok {
		return
	}
	invitationID := chi.URLParam(r, "id")
	if err := h.store.RevokeInvitation(r.Context(), acting.handle, invitationID); err != nil {
		writeStoreError(w, "revokeInvitation", err)
		return
	}
	h.auditInvitation(r, acting, database.AuditInvitationRevoked, invitationID, invitationID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listMyInvitations(w http.ResponseWriter, r *http.Request) {
	invitations, err := h.store.ListReceivedInvitations(r.Context(), userOf(r))
	if err != nil {
		writeStoreError(w, "listReceivedInvitations", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"invitations": invitations})
}

func (h *Handler) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	userID := userOf(r)
	invitation, err := h.store.AcceptInvitation(r.Context(), userID, chi.URLParam(r, "id"))
	if err != nil {
		writeStoreError(w, "acceptInvitation", err)
		return
	}
	acting := &organizationContext{userID: userID, handle: invitation.Organization.Handle}
	h.auditInvitation(r, acting, database.AuditInvitationAccepted, invitation.ID, userID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) declineInvitation(w http.ResponseWriter, r *http.Request) {
	userID := userOf(r)
	invitation, err := h.store.DeclineInvitation(r.Context(), userID, chi.URLParam(r, "id"))
	if err != nil {
		writeStoreError(w, "declineInvitation", err)
		return
	}
	acting := &organizationContext{userID: userID, handle: invitation.Organization.Handle}
	h.auditInvitation(r, acting, database.AuditInvitationDeclined, invitation.ID, userID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listAudit(w http.ResponseWriter, r *http.Request) {
	acting, ok := h.permitted(w, r, ownership.AuditView)
	if !ok {
		return
	}
	before, ok := auditCursor(w, r)
	if !ok {
		return
	}
	page, err := h.store.ListAudit(r.Context(), acting.handle, before, queryLimit(r))
	if err != nil {
		writeStoreError(w, "listAudit", err)
		return
	}
	respond.JSON(w, http.StatusOK, page)
}

// auditCursor reads `before`, the nextCursor of the previous page.
func auditCursor(w http.ResponseWriter, r *http.Request) (time.Time, bool) {
	raw := r.URL.Query().Get("before")
	if raw == "" {
		return time.Time{}, true
	}
	before, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid_cursor", "before is not a cursor from this endpoint")
		return time.Time{}, false
	}
	return before, true
}

func queryLimit(r *http.Request) int {
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil {
		return 0
	}
	return limit
}
