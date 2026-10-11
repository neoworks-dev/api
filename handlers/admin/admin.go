// Package admin serves the platform administration of Neoworks: deciding app
// reviews, verifying organizations and tuning the rate limits of a client.
// Administrators are the members of the seeded neoworks organization that hold
// the platform.admin permission.
package admin

import (
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/config"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/ownership"
	"github.com/neoworks/auth/storage/database"
)

// queueStatuses are the statuses the review queue lists; apps that never asked
// for review are not queued.
var queueStatuses = []string{
	database.ReviewStatusPending, database.ReviewStatusApproved, database.ReviewStatusRejected, database.ReviewStatusSuspended,
}

const (
	maxRequestBody     = 8 << 10
	maxReasonRunes     = 500
	maxMultiplier      = 100.0
	defaultQueueStatus = database.ReviewStatusPending
)

type Handler struct {
	store *database.SurrealStore
}

func NewHandler(store *database.SurrealStore) *Handler {
	return &Handler{store: store}
}

// RegisterAuthenticated mounts the routes. The router must admit only account
// principals of the web dashboard's client.
func (h *Handler) RegisterAuthenticated(router chi.Router) {
	router.Get("/api/v1/admin/session", h.session)
	router.Get("/api/v1/admin/reviews", h.listReviews)
	router.Post("/api/v1/admin/apps/{clientId}/review", h.decide)
	router.Put("/api/v1/admin/apps/{clientId}/rate-limit", h.setRateLimit)
	router.Put("/api/v1/admin/organizations/{handle}/verified", h.setVerified)
}

// administrator answers 403 unless the caller is a platform administrator.
func (h *Handler) administrator(w http.ResponseWriter, r *http.Request) (string, bool) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	admin, err := h.store.IsPlatformAdmin(r.Context(), principal.UserID)
	if err != nil {
		respond.StoreError(w, "isPlatformAdmin", err)
		return "", false
	}
	if !admin {
		respond.MissingPermission(w, ownership.PlatformAdmin)
		return "", false
	}
	return principal.UserID, true
}

func (h *Handler) session(w http.ResponseWriter, r *http.Request) {
	principal, _ := middleware.PrincipalFromContext(r.Context())
	admin, err := h.store.IsPlatformAdmin(r.Context(), principal.UserID)
	if err != nil {
		respond.StoreError(w, "isPlatformAdmin", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]bool{"admin": admin})
}

// reviewItem is an app in the review queue with what the reviewer judges it by.
type reviewItem struct {
	App              *database.App             `json:"app"`
	LogoURL          *string                   `json:"logoUrl"`
	PrivacyPolicyURL string                    `json:"privacyPolicyUrl"`
	SupportContact   string                    `json:"supportContact"`
	Scopes           []database.RequestedScope `json:"scopes"`
}

func logoURL(app *database.App) *string {
	if app.LogoAssetID == nil {
		return nil
	}
	url := config.AssetURL(*app.LogoAssetID)
	return &url
}

func (h *Handler) listReviews(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.administrator(w, r); !ok {
		return
	}
	status := r.URL.Query().Get("status")
	if status == "" {
		status = defaultQueueStatus
	}
	if !slices.Contains(queueStatuses, status) {
		fieldError(w, "status", "status must be pending, approved, rejected or suspended")
		return
	}
	queue, err := h.store.ListReviewQueue(r.Context(), status)
	if err != nil {
		respond.StoreError(w, "listReviewQueue", err)
		return
	}
	items := make([]reviewItem, 0, len(queue))
	for _, entry := range queue {
		items = append(items, reviewItem{
			App: entry.App, LogoURL: logoURL(entry.App), PrivacyPolicyURL: entry.PrivacyPolicyURL,
			SupportContact: entry.SupportContact, Scopes: entry.Scopes,
		})
	}
	respond.JSON(w, http.StatusOK, map[string]any{"items": items})
}

type decisionRequest struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

var decisionAudit = map[database.ReviewDecision]string{
	database.DecisionApprove: database.AuditAppReviewApproved,
	database.DecisionReject:  database.AuditAppReviewRejected,
	database.DecisionSuspend: database.AuditAppSuspended,
}

func (h *Handler) decide(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.administrator(w, r)
	if !ok {
		return
	}
	var request decisionRequest
	if !respond.Decode(w, r, &request, maxRequestBody) {
		return
	}
	decision := database.ReviewDecision(request.Decision)
	reason := strings.TrimSpace(request.Reason)
	if !validDecision(w, decision, reason) {
		return
	}
	app, err := h.store.DecideReview(r.Context(), chi.URLParam(r, "clientId"), decision, reason)
	if errors.Is(err, database.ErrReviewState) {
		respond.Error(w, http.StatusConflict, "review_state", "the app is not in a status this decision can be made from")
		return
	}
	if err != nil {
		respond.StoreError(w, "decideReview", err)
		return
	}
	h.audit(r, adminID, app, decisionAudit[decision], reason)
	respond.JSON(w, http.StatusOK, map[string]any{"app": app, "logoUrl": logoURL(app)})
}

func validDecision(w http.ResponseWriter, decision database.ReviewDecision, reason string) bool {
	if !decision.IsKnown() {
		fieldError(w, "decision", "decision must be approve, reject or suspend")
		return false
	}
	if decision.NeedsReason() && reason == "" {
		fieldError(w, "reason", "tell the developer why")
		return false
	}
	if utf8.RuneCountInString(reason) > maxReasonRunes {
		fieldError(w, "reason", "the reason is too long")
		return false
	}
	return true
}

func fieldError(w http.ResponseWriter, field string, message string) {
	respond.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "field": field, "message": message})
}

// audit records the decision in the audit log of the app's organization, with
// the administrator as the actor. A failure is logged: the decision stands.
func (h *Handler) audit(r *http.Request, adminID string, app *database.App, action string, reason string) {
	if app.Owner.Kind != database.OwnerKindOrganization {
		return
	}
	details := map[string]any{}
	if reason != "" {
		details["reason"] = reason
	}
	err := h.store.RecordAudit(r.Context(), database.AuditInput{
		Organization: app.Owner.Handle, ActorID: adminID, Action: action,
		Target:  database.AuditTarget{Kind: "app", ID: app.ID, Label: app.Name},
		Details: details,
	})
	if err != nil {
		slog.Error("record admin audit", "organization", app.Owner.Handle, "action", action, "error", err)
	}
}

type rateLimitRequest struct {
	Multiplier *float64 `json:"multiplier"`
}

func (h *Handler) setRateLimit(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.administrator(w, r); !ok {
		return
	}
	var request rateLimitRequest
	if !respond.Decode(w, r, &request, maxRequestBody) {
		return
	}
	if request.Multiplier != nil && (*request.Multiplier <= 0 || *request.Multiplier > maxMultiplier) {
		fieldError(w, "multiplier", "multiplier must be above 0 and at most 100, or null")
		return
	}
	if err := h.store.SetRateLimitMultiplier(r.Context(), chi.URLParam(r, "clientId"), request.Multiplier); err != nil {
		respond.StoreError(w, "setRateLimitMultiplier", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"multiplier": request.Multiplier})
}

type verifiedRequest struct {
	Verified bool `json:"verified"`
}

func (h *Handler) setVerified(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.administrator(w, r)
	if !ok {
		return
	}
	var request verifiedRequest
	if !respond.Decode(w, r, &request, maxRequestBody) {
		return
	}
	handle := chi.URLParam(r, "handle")
	owner, err := h.store.GetOwner(r.Context(), handle)
	if err != nil || owner.Kind != database.OwnerKindOrganization {
		respond.Error(w, http.StatusNotFound, "not_found", "no such organization")
		return
	}
	changed, err := h.store.SetOrganizationVerified(r.Context(), handle, request.Verified)
	if err != nil {
		respond.StoreError(w, "setOrganizationVerified", err)
		return
	}
	if changed {
		h.auditVerified(r, adminID, *owner, request.Verified)
	}
	owner.Verified = request.Verified
	respond.JSON(w, http.StatusOK, owner)
}

func (h *Handler) auditVerified(r *http.Request, adminID string, owner database.Owner, verified bool) {
	err := h.store.RecordAudit(r.Context(), database.AuditInput{
		Organization: owner.Handle, ActorID: adminID, Action: database.AuditOrganizationVerifiedChanged,
		Target:  database.AuditTarget{Kind: "organization", ID: owner.Handle, Label: owner.DisplayName},
		Details: map[string]any{"verified": verified},
	})
	if err != nil {
		slog.Error("record verified audit", "organization", owner.Handle, "error", err)
	}
}
