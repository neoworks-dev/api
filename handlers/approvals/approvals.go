package approvals

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/push"
	"github.com/neoworks/auth/storage/cache"
	"github.com/neoworks/auth/storage/database"
)

type Handler struct {
	store *database.SurrealStore
	redis *cache.RedisStore
	push  push.Sender
}

func NewHandler(store *database.SurrealStore, redis *cache.RedisStore, sender push.Sender) *Handler {
	return &Handler{store: store, redis: redis, push: sender}
}

func (h *Handler) RegisterAuthenticated(r chi.Router) {
	r.Get("/api/v1/approvals", h.listPending)
	r.Get("/api/v1/approvals/history", h.history)
	r.Get("/api/v1/approvals/stream", h.stream)
	r.Get("/api/v1/approvals/{id}", h.detail)
	r.Post("/api/v1/approvals/{id}/approve", h.approve)
	r.Post("/api/v1/approvals/{id}/deny", h.deny)
	r.Post("/api/v1/approvals/qr-signin", h.createQrSignin)
	r.Post("/api/v1/push-tokens", h.registerPushToken)
}

// createQrSignin turns a scanned sign-in QR into a pending approval request for
// the authenticated user. The oauth login page shows a QR carrying only the
// login_challenge (it doesn't know who is signing in); the app — which is the
// user — scans it and creates the request here. It is left PENDING on purpose:
// the user still confirms it on the normal request-detail screen, which is what
// writes the approval result the waiting browser polls for.
func (h *Handler) createQrSignin(w http.ResponseWriter, r *http.Request) {
	userID, ok := subject(w, r)
	if !ok {
		return
	}

	var body struct {
		LoginChallenge string `json:"login_challenge"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.LoginChallenge == "" {
		jsonError(w, "login_challenge required", http.StatusBadRequest)
		return
	}

	challenge, err := h.redis.GetLoginChallenge(r.Context(), body.LoginChallenge)
	if err != nil || challenge == nil {
		jsonError(w, "invalid or expired sign-in request", http.StatusBadRequest)
		return
	}

	label := "Scanned QR code"
	req, err := h.store.CreateApprovalRequest(r.Context(), &database.CreateApprovalParams{
		UserID:          userID,
		Type:            "signin",
		Client:          challenge.ClientID,
		Scopes:          challenge.Scopes,
		RequestingLabel: &label,
		LoginChallenge:  &challenge.ID,
		ExpiresAt:       challenge.ExpiresAt,
	})
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, req)
}

// ── Reads ───────────────────────────────────────────────────────────────────

func (h *Handler) listPending(w http.ResponseWriter, r *http.Request) {
	userID, ok := subject(w, r)
	if !ok {
		return
	}
	requests, err := h.store.ListPendingApprovals(r.Context(), userID)
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, nonNil(requests))
}

func (h *Handler) history(w http.ResponseWriter, r *http.Request) {
	userID, ok := subject(w, r)
	if !ok {
		return
	}
	requests, err := h.store.ListApprovalHistory(r.Context(), userID, 20)
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, nonNil(requests))
}

func (h *Handler) detail(w http.ResponseWriter, r *http.Request) {
	userID, ok := subject(w, r)
	if !ok {
		return
	}
	req, err := h.store.GetApprovalRequest(r.Context(), userID, chi.URLParam(r, "id"))
	if errors.Is(err, database.ErrNotFound) {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, req)
}

// stream is a long-poll: it returns as soon as the user has pending requests,
// or an empty list after a short timeout. The app reconnects in a loop. NATS/SSE
// can later push to this same endpoint without changing the contract.
func (h *Handler) stream(w http.ResponseWriter, r *http.Request) {
	userID, ok := subject(w, r)
	if !ok {
		return
	}

	deadline := time.After(25 * time.Second)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		requests, err := h.store.ListPendingApprovals(r.Context(), userID)
		if err != nil {
			jsonError(w, "server error", http.StatusInternalServerError)
			return
		}
		if len(requests) > 0 {
			writeJSON(w, requests)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-deadline:
			writeJSON(w, []*oauth.ApprovalRequest{})
			return
		case <-ticker.C:
		}
	}
}

// ── Decisions ───────────────────────────────────────────────────────────────

func (h *Handler) approve(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, "approved")
}

func (h *Handler) deny(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, "denied")
}

func (h *Handler) decide(w http.ResponseWriter, r *http.Request, status string) {
	userID, ok := subject(w, r)
	if !ok {
		return
	}

	req, err := h.store.DecideApprovalRequest(r.Context(), userID, chi.URLParam(r, "id"), status)
	if errors.Is(err, database.ErrNotFound) {
		jsonError(w, "request not found or already decided", http.StatusConflict)
		return
	}
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	// Signal the waiting login page (cross-process via Redis) for sign-in requests.
	if req.Type == "signin" && req.LoginChallenge != nil {
		_ = h.redis.SetApprovalResult(r.Context(), *req.LoginChallenge, cache.ApprovalResult{
			Status: status,
			UserID: userID,
		})
	}

	writeJSON(w, req)
}

// ── Push token registration ───────────────────────────────────────────────────

func (h *Handler) registerPushToken(w http.ResponseWriter, r *http.Request) {
	userID, ok := subject(w, r)
	if !ok {
		return
	}

	var body struct {
		Platform string  `json:"platform"`
		Token    string  `json:"token"`
		DeviceID *string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Token == "" {
		jsonError(w, "platform and token required", http.StatusBadRequest)
		return
	}
	if body.Platform != "fcm" && body.Platform != "apns" {
		jsonError(w, "platform must be fcm or apns", http.StatusBadRequest)
		return
	}

	if err := h.store.UpsertPushToken(r.Context(), userID, body.DeviceID, body.Platform, body.Token); err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func subject(w http.ResponseWriter, r *http.Request) (string, bool) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return "", false
	}
	return claims.Subject, true
}

func nonNil(requests []*oauth.ApprovalRequest) []*oauth.ApprovalRequest {
	if requests == nil {
		return []*oauth.ApprovalRequest{}
	}
	return requests
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
