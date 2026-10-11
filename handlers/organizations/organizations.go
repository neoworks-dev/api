// Package organizations serves handles, organizations, their members,
// invitations and audit log: the owners that apps and registry scopes belong
// to. Every route acts for the signed-in account through the web dashboard.
package organizations

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/ownership"
	"github.com/neoworks/auth/storage/database"
)

const (
	maxRequestBody        = 16 << 10
	maxDisplayNameRunes   = 100
	organizationPathParam = "handle"
)

type Handler struct {
	store *database.SurrealStore
}

func NewHandler(store *database.SurrealStore) *Handler {
	return &Handler{store: store}
}

// RegisterAuthenticated mounts the routes. The router must admit only account
// principals of the web dashboard's client: these routes act for the account,
// so an app holding an account token must not reach them.
func (h *Handler) RegisterAuthenticated(router chi.Router) {
	router.Get("/api/v1/me/handle", h.getMyHandle)
	router.Put("/api/v1/me/handle", h.claimMyHandle)
	router.Get("/api/v1/handles/{handle}/availability", h.availability)
	router.Get("/api/v1/me/owners", h.listMyOwners)

	router.Post("/api/v1/organizations", h.createOrganization)
	router.Get("/api/v1/organizations/{handle}", h.getOrganization)
	router.Patch("/api/v1/organizations/{handle}", h.renameOrganization)
	router.Post("/api/v1/organizations/{handle}/archive", h.archiveOrganization)

	router.Get("/api/v1/organizations/{handle}/members", h.listMembers)
	router.Put("/api/v1/organizations/{handle}/members/{userId}/grants", h.setMemberGrants)
	router.Delete("/api/v1/organizations/{handle}/members/{userId}", h.removeMember)

	router.Get("/api/v1/organizations/{handle}/invitations", h.listInvitations)
	router.Post("/api/v1/organizations/{handle}/invitations", h.createInvitation)
	router.Delete("/api/v1/organizations/{handle}/invitations/{id}", h.revokeInvitation)
	router.Get("/api/v1/me/invitations", h.listMyInvitations)
	router.Post("/api/v1/me/invitations/{id}/accept", h.acceptInvitation)
	router.Post("/api/v1/me/invitations/{id}/decline", h.declineInvitation)

	router.Get("/api/v1/organizations/{handle}/audit", h.listAudit)
}

// userOf returns the signed-in user.
func userOf(r *http.Request) string {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	return principal.UserID
}

// organizationContext is a request acting on one organization.
type organizationContext struct {
	userID string
	handle string
	grants []ownership.Grant
}

// member resolves the organization in the path and the caller's grants in it.
// Non-members get 404: membership is private.
func (h *Handler) member(w http.ResponseWriter, r *http.Request) (*organizationContext, bool) {
	userID := userOf(r)
	handle := chi.URLParam(r, organizationPathParam)
	grants, err := h.store.GrantsFor(r.Context(), userID, handle)
	if errors.Is(err, database.ErrForbidden) {
		respond.Error(w, http.StatusNotFound, "not_found", "not found")
		return nil, false
	}
	if err != nil {
		writeStoreError(w, "grantsFor", err)
		return nil, false
	}
	if !h.isOrganization(w, r, handle) {
		return nil, false
	}
	return &organizationContext{userID: userID, handle: handle, grants: grants}, true
}

// isOrganization refuses personal handles on organization routes.
func (h *Handler) isOrganization(w http.ResponseWriter, r *http.Request, handle string) bool {
	owner, err := h.store.GetOwner(r.Context(), handle)
	if err != nil {
		writeStoreError(w, "getOwner", err)
		return false
	}
	if owner.Kind != database.OwnerKindOrganization {
		respond.Error(w, http.StatusNotFound, "not_found", "not found")
		return false
	}
	return true
}

// permitted resolves the organization and requires an organization-wide permission.
func (h *Handler) permitted(w http.ResponseWriter, r *http.Request, permission ownership.Permission) (*organizationContext, bool) {
	acting, ok := h.member(w, r)
	if !ok {
		return nil, false
	}
	if !ownership.Allows(acting.grants, permission, "") {
		respond.MissingPermission(w, permission)
		return nil, false
	}
	return acting, true
}

// writable additionally refuses changes to an archived organization.
func (h *Handler) writable(w http.ResponseWriter, r *http.Request, permission ownership.Permission) (*organizationContext, bool) {
	acting, ok := h.permitted(w, r, permission)
	if !ok {
		return nil, false
	}
	archived, err := h.store.IsArchived(r.Context(), acting.handle)
	if err != nil {
		writeStoreError(w, "isArchived", err)
		return nil, false
	}
	if archived {
		respond.Error(w, http.StatusConflict, "archived", "the organization is archived")
		return nil, false
	}
	return acting, true
}

// writeStoreError maps the ownership errors, then falls back to respond.StoreError.
func writeStoreError(w http.ResponseWriter, operation string, err error) {
	conflicts := map[error][2]string{
		database.ErrHandleTaken:      {"handle_taken", "that handle is taken"},
		database.ErrHandleAlreadySet: {"handle_already_set", "your handle is already set and never changes"},
		database.ErrHandleRequired:   {"handle_required", "pick your handle first"},
		database.ErrAlreadyMember:    {"already_member", "already a member of this organization"},
		database.ErrOwnsApps:         {"owns_apps", "the organization still owns apps"},
	}
	for known, codeAndMessage := range conflicts {
		if errors.Is(err, known) {
			respond.Error(w, http.StatusConflict, codeAndMessage[0], codeAndMessage[1])
			return
		}
	}
	respond.StoreError(w, operation, err)
}

func writeChangeProblem(w http.ResponseWriter, problem ownership.ChangeProblem) {
	switch problem {
	case ownership.ProblemMissingPermission:
		respond.MissingPermission(w, ownership.MembersManage)
	case ownership.ProblemEscalation:
		respond.Error(w, http.StatusForbidden, "escalation", "you can only grant or remove permissions you hold, at the same or a wider reach")
	case ownership.ProblemLastManager:
		respond.Error(w, http.StatusConflict, "last_members_manager", "the organization needs at least one member with members.manage")
	default:
		respond.Error(w, http.StatusBadRequest, "invalid_grant", "a grant names an unknown permission or a reach it does not allow")
	}
}

// audit records an action; a failure is logged, since the action already happened.
func (h *Handler) audit(r *http.Request, input database.AuditInput) {
	if err := h.store.RecordAudit(r.Context(), input); err != nil {
		slog.Error("record organization audit", "organization", input.Organization, "action", input.Action, "error", err)
	}
}

func validDisplayName(displayName string) bool {
	trimmed := strings.TrimSpace(displayName)
	return trimmed != "" && utf8.RuneCountInString(trimmed) <= maxDisplayNameRunes
}
