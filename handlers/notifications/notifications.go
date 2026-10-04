// Package notifications serves the user's in-app notification feed and pushes
// new notifications to their devices.
package notifications

import (
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/push"
	"github.com/neoworks/auth/storage/database"
)

const (
	maxNotificationBody = 16 << 10
	sendScope           = "notification:write"
)

type Handler struct {
	store *database.SurrealStore
	push  push.Sender
}

func NewHandler(store *database.SurrealStore, sender push.Sender) *Handler {
	return &Handler{store: store, push: sender}
}

func (h *Handler) RegisterAuthenticated(router chi.Router) {
	router.Get("/api/v1/notifications", h.list)
	router.Post("/api/v1/notifications", h.send)
	router.Post("/api/v1/notifications/{id}/read", h.markRead)
}

func subjectOf(w http.ResponseWriter, r *http.Request) (string, bool) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil || claims.Subject == "" {
		respond.Error(w, http.StatusUnauthorized, "invalid_token", "no user")
		return "", false
	}
	return claims.Subject, true
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	userID, ok := subjectOf(w, r)
	if !ok {
		return
	}
	notifications, err := h.store.ListNotifications(r.Context(), userID)
	if err != nil {
		respond.StoreError(w, "listNotifications", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"notifications": notifications})
}

type sendRequest struct {
	UserID string  `json:"userId"`
	Title  string  `json:"title"`
	Body   string  `json:"body"`
	URL    *string `json:"url"`
}

// send creates a notification and pushes it to the recipient's devices. The
// recipient is the caller unless userId names someone else, which needs the
// notification:write scope.
func (h *Handler) send(w http.ResponseWriter, r *http.Request) {
	callerID, ok := subjectOf(w, r)
	if !ok {
		return
	}
	var request sendRequest
	if !respond.Decode(w, r, &request, maxNotificationBody) {
		return
	}
	if request.Title == "" || request.Body == "" {
		respond.Error(w, http.StatusBadRequest, "invalid_request", "title and body are required")
		return
	}
	recipient := callerID
	if request.UserID != "" && request.UserID != callerID {
		if !slices.Contains(middleware.ClaimFromContext(r.Context()).Scope, sendScope) {
			respond.Error(w, http.StatusForbidden, "forbidden", "sending to another user requires the "+sendScope+" scope")
			return
		}
		recipient = request.UserID
	}

	notification, err := h.store.CreateNotification(r.Context(), database.CreateNotificationParams{
		UserID: recipient, Title: request.Title, Body: request.Body, URL: request.URL,
	})
	if err != nil {
		respond.StoreError(w, "sendNotification", err)
		return
	}
	h.deliver(r, recipient, notification)
	respond.JSON(w, http.StatusOK, notification)
}

// deliver pushes the notification to the recipient's devices. It is best-effort:
// a push failure never fails the request.
func (h *Handler) deliver(r *http.Request, recipient string, notification *database.Notification) {
	tokens, err := h.store.ListPushTokensForUser(r.Context(), recipient)
	if err != nil || len(tokens) == 0 {
		return
	}
	data := map[string]string{"type": "notification", "notification_id": notification.ID}
	if notification.URL != nil {
		data["url"] = *notification.URL
	}
	_ = h.push.Send(r.Context(), tokens, notification.Title, notification.Body, data)
}

func (h *Handler) markRead(w http.ResponseWriter, r *http.Request) {
	userID, ok := subjectOf(w, r)
	if !ok {
		return
	}
	if err := h.store.MarkNotificationRead(r.Context(), userID, chi.URLParam(r, "id")); err != nil {
		respond.StoreError(w, "markNotificationRead", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
