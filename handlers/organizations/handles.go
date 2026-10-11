package organizations

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/ownership"
	"github.com/neoworks/auth/storage/database"
)

func (h *Handler) getMyHandle(w http.ResponseWriter, r *http.Request) {
	handle, err := h.store.GetUserHandle(r.Context(), userOf(r))
	if err != nil {
		writeStoreError(w, "getUserHandle", err)
		return
	}
	if handle == "" {
		respond.JSON(w, http.StatusOK, map[string]any{"handle": nil})
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"handle": handle})
}

type handleRequest struct {
	Handle string `json:"handle"`
}

func (h *Handler) claimMyHandle(w http.ResponseWriter, r *http.Request) {
	var request handleRequest
	if !respond.Decode(w, r, &request, maxRequestBody) {
		return
	}
	if !checkClaimable(w, request.Handle) {
		return
	}
	if err := h.store.ClaimUserHandle(r.Context(), userOf(r), request.Handle); err != nil {
		writeStoreError(w, "claimUserHandle", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]string{"handle": request.Handle})
}

// checkClaimable refuses handles whose form or reservation rules out claiming.
func checkClaimable(w http.ResponseWriter, handle string) bool {
	problem := ownership.CheckHandle(handle)
	if problem == ownership.HandleInvalid {
		respond.JSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_handle", "field": "handle",
			"message": "2 to 39 lowercase letters, digits or hyphens, starting with a letter or digit",
		})
		return false
	}
	if problem == ownership.HandleReserved {
		respond.Error(w, http.StatusConflict, "handle_taken", "that handle is reserved")
		return false
	}
	return true
}

func (h *Handler) availability(w http.ResponseWriter, r *http.Request) {
	handle := strings.TrimSpace(chi.URLParam(r, "handle"))
	problem := ownership.CheckHandle(handle)
	if problem != "" {
		respond.JSON(w, http.StatusOK, map[string]any{"available": false, "reason": string(problem)})
		return
	}
	taken, err := h.store.IsHandleTaken(r.Context(), handle)
	if err != nil {
		writeStoreError(w, "isHandleTaken", err)
		return
	}
	if taken {
		respond.JSON(w, http.StatusOK, map[string]any{"available": false, "reason": "taken"})
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"available": true})
}

func (h *Handler) listMyOwners(w http.ResponseWriter, r *http.Request) {
	owners, err := h.store.OwnersOf(r.Context(), userOf(r))
	if err != nil {
		writeStoreError(w, "ownersOf", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"owners": owners})
}

type createOrganizationRequest struct {
	Handle      string `json:"handle"`
	DisplayName string `json:"displayName"`
}

func (h *Handler) createOrganization(w http.ResponseWriter, r *http.Request) {
	var request createOrganizationRequest
	if !respond.Decode(w, r, &request, maxRequestBody) {
		return
	}
	if !checkClaimable(w, request.Handle) || !checkDisplayName(w, request.DisplayName) {
		return
	}
	userID := userOf(r)
	organization, err := h.store.CreateOrganization(r.Context(), userID, request.Handle, strings.TrimSpace(request.DisplayName))
	if err != nil {
		writeStoreError(w, "createOrganization", err)
		return
	}
	h.audit(r, database.AuditInput{
		Organization: organization.Handle, ActorID: userID, Action: database.AuditOrganizationCreated,
		Target: database.AuditTarget{Kind: "organization", ID: organization.Handle, Label: organization.DisplayName},
	})
	respond.JSON(w, http.StatusCreated, organization)
}

func checkDisplayName(w http.ResponseWriter, displayName string) bool {
	if validDisplayName(displayName) {
		return true
	}
	respond.JSON(w, http.StatusBadRequest, map[string]string{
		"error": "invalid_display_name", "field": "displayName", "message": "1 to 100 characters",
	})
	return false
}

func (h *Handler) getOrganization(w http.ResponseWriter, r *http.Request) {
	acting, ok := h.member(w, r)
	if !ok {
		return
	}
	h.respondOrganization(w, r, acting, http.StatusOK)
}

func (h *Handler) respondOrganization(w http.ResponseWriter, r *http.Request, acting *organizationContext, status int) {
	organization, err := h.store.GetOrganization(r.Context(), acting.handle, acting.userID)
	if err != nil {
		writeStoreError(w, "getOrganization", err)
		return
	}
	respond.JSON(w, status, organization)
}

type renameRequest struct {
	DisplayName string `json:"displayName"`
}

func (h *Handler) renameOrganization(w http.ResponseWriter, r *http.Request) {
	acting, ok := h.writable(w, r, ownership.OrganizationManage)
	if !ok {
		return
	}
	var request renameRequest
	if !respond.Decode(w, r, &request, maxRequestBody) || !checkDisplayName(w, request.DisplayName) {
		return
	}
	displayName := strings.TrimSpace(request.DisplayName)
	if err := h.store.RenameOrganization(r.Context(), acting.handle, displayName); err != nil {
		writeStoreError(w, "renameOrganization", err)
		return
	}
	h.audit(r, database.AuditInput{
		Organization: acting.handle, ActorID: acting.userID, Action: database.AuditOrganizationRenamed,
		Target: database.AuditTarget{Kind: "organization", ID: acting.handle, Label: displayName},
	})
	h.respondOrganization(w, r, acting, http.StatusOK)
}

func (h *Handler) archiveOrganization(w http.ResponseWriter, r *http.Request) {
	acting, ok := h.writable(w, r, ownership.OrganizationManage)
	if !ok {
		return
	}
	if err := h.store.ArchiveOrganization(r.Context(), acting.handle); err != nil {
		writeStoreError(w, "archiveOrganization", err)
		return
	}
	h.audit(r, database.AuditInput{
		Organization: acting.handle, ActorID: acting.userID, Action: database.AuditOrganizationArchived,
		Target: database.AuditTarget{Kind: "organization", ID: acting.handle, Label: acting.handle},
	})
	h.respondOrganization(w, r, acting, http.StatusOK)
}
