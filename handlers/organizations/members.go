package organizations

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/ownership"
	"github.com/neoworks/auth/storage/database"
)

func (h *Handler) listMembers(w http.ResponseWriter, r *http.Request) {
	acting, ok := h.member(w, r)
	if !ok {
		return
	}
	members, err := h.store.ListMembers(r.Context(), acting.handle)
	if err != nil {
		writeStoreError(w, "listMembers", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"members": members})
}

type grantsRequest struct {
	Grants []ownership.Grant `json:"grants"`
}

func (h *Handler) setMemberGrants(w http.ResponseWriter, r *http.Request) {
	acting, ok := h.writable(w, r, ownership.MembersManage)
	if !ok {
		return
	}
	var request grantsRequest
	if !respond.Decode(w, r, &request, maxRequestBody) {
		return
	}
	memberID := chi.URLParam(r, "userId")
	after := ownership.Normalize(request.Grants)
	if !h.checkGrantChange(w, r, acting, memberID, after) || !h.appsExist(w, r, after) {
		return
	}
	if err := h.store.SetMemberGrants(r.Context(), acting.handle, memberID, after); err != nil {
		writeStoreError(w, "setMemberGrants", err)
		return
	}
	h.respondMember(w, r, acting, memberID, database.AuditMemberGrantsChanged)
}

// checkGrantChange applies the member rules to replacing memberID's grants.
func (h *Handler) checkGrantChange(w http.ResponseWriter, r *http.Request, acting *organizationContext, memberID string, after []ownership.Grant) bool {
	members, err := h.store.MemberGrantsByUser(r.Context(), acting.handle)
	if err != nil {
		writeStoreError(w, "memberGrantsByUser", err)
		return false
	}
	before, isMember := members[memberID]
	if !isMember {
		respond.Error(w, http.StatusNotFound, "not_found", "not a member")
		return false
	}
	problem := ownership.CheckGrantChange(ownership.GrantChange{
		ActorGrants: acting.grants, Before: before, After: after, MemberID: memberID, Members: members,
	})
	if problem != "" {
		writeChangeProblem(w, problem)
		return false
	}
	return true
}

// appsExist refuses per-app grants for apps that do not exist.
func (h *Handler) appsExist(w http.ResponseWriter, r *http.Request, grants []ownership.Grant) bool {
	for _, grant := range grants {
		if grant.AppID == nil {
			continue
		}
		if _, err := h.store.GetClient(r.Context(), *grant.AppID); err != nil {
			respond.JSON(w, http.StatusBadRequest, map[string]string{
				"error": "unknown_app", "field": "grants", "message": "no app " + *grant.AppID,
			})
			return false
		}
	}
	return true
}

func (h *Handler) respondMember(w http.ResponseWriter, r *http.Request, acting *organizationContext, memberID string, action string) {
	member, err := h.store.GetMember(r.Context(), acting.handle, memberID)
	if err != nil {
		writeStoreError(w, "getMember", err)
		return
	}
	h.audit(r, database.AuditInput{
		Organization: acting.handle, ActorID: acting.userID, Action: action,
		Target:  database.AuditTarget{Kind: "member", ID: memberID, Label: member.DisplayName},
		Details: map[string]any{"grants": member.Grants},
	})
	respond.JSON(w, http.StatusOK, member)
}

// removeMember removes a member, or lets the caller leave when they name
// themselves; leaving needs no permission.
func (h *Handler) removeMember(w http.ResponseWriter, r *http.Request) {
	acting, ok := h.member(w, r)
	if !ok {
		return
	}
	memberID := chi.URLParam(r, "userId")
	if memberID == acting.userID {
		h.leave(w, r, acting)
		return
	}
	acting, ok = h.writable(w, r, ownership.MembersManage)
	if !ok || !h.checkGrantChange(w, r, acting, memberID, nil) {
		return
	}
	h.deleteMember(w, r, acting, memberID, database.AuditMemberRemoved)
}

func (h *Handler) leave(w http.ResponseWriter, r *http.Request, acting *organizationContext) {
	members, err := h.store.MemberGrantsByUser(r.Context(), acting.handle)
	if err != nil {
		writeStoreError(w, "memberGrantsByUser", err)
		return
	}
	if problem := ownership.CheckLeave(members, acting.userID); problem != "" {
		writeChangeProblem(w, problem)
		return
	}
	h.deleteMember(w, r, acting, acting.userID, database.AuditMemberLeft)
}

func (h *Handler) deleteMember(w http.ResponseWriter, r *http.Request, acting *organizationContext, memberID string, action string) {
	member, err := h.store.GetMember(r.Context(), acting.handle, memberID)
	if errors.Is(err, database.ErrNotFound) {
		respond.Error(w, http.StatusNotFound, "not_found", "not a member")
		return
	}
	if err != nil {
		writeStoreError(w, "getMember", err)
		return
	}
	if err := h.store.RemoveMember(r.Context(), acting.handle, memberID); err != nil {
		writeStoreError(w, "removeMember", err)
		return
	}
	h.audit(r, database.AuditInput{
		Organization: acting.handle, ActorID: acting.userID, Action: action,
		Target: database.AuditTarget{Kind: "member", ID: memberID, Label: member.DisplayName},
	})
	w.WriteHeader(http.StatusNoContent)
}
