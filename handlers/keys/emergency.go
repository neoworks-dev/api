package keys

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/database"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

const recoverySessionTTL = 30 * time.Minute

// recordID renders a SurrealDB record id's key as a plain string for JSON + lookups.
func recordID(r *models.RecordID) string {
	if r == nil {
		return ""
	}
	if s, ok := r.ID.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", r.ID)
}

// RegisterEmergency mounts the social-recovery endpoints. Called from the keys
// handler's authenticated registration.
func (h *Handler) RegisterEmergency(r chi.Router) {
	r.Get("/api/v1/keys/public-keys", h.guardianPublicKeys)
	r.Get("/api/v1/keys/emergency-contacts", h.listEmergencyContacts)
	r.Post("/api/v1/keys/emergency-contacts", h.saveEmergencyContacts)
	r.Delete("/api/v1/keys/emergency-contacts", h.clearEmergencyContacts)
	r.Post("/api/v1/keys/recovery-sessions", h.createRecoverySession)
	r.Get("/api/v1/keys/recovery-sessions/{id}", h.getRecoverySession)
	r.Post("/api/v1/keys/recovery-sessions/{id}/shares", h.submitRecoveryShare)
	r.Post("/api/v1/keys/recovery-sessions/{id}/complete", h.completeRecoverySession)
	r.Get("/api/v1/keys/recovery-requests", h.listRecoveryRequests)
}

// guardianPublicKeys resolves an email to its account + device public keys, so
// the owner can seal a guardian's share to each of that guardian's devices.
func (h *Handler) guardianPublicKeys(w http.ResponseWriter, r *http.Request) {
	if middleware.ClaimFromContext(r.Context()) == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	email := r.URL.Query().Get("email")
	if email == "" {
		jsonError(w, "missing email", http.StatusBadRequest)
		return
	}

	userID, err := h.store.GetUserIDByEmail(r.Context(), email)
	if errors.Is(err, database.ErrNotFound) {
		jsonError(w, "no account for that email", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	keys, err := h.store.ListDevicePublicKeys(r.Context(), userID)
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}
	if len(keys) == 0 {
		jsonError(w, "that account has no devices to guard with", http.StatusConflict)
		return
	}

	writeJSON(w, map[string]any{"user_id": userID, "public_keys": keys})
}

type saveContactsBody struct {
	SocialWrappedAMK string `json:"social_wrapped_amk"`
	Threshold        int    `json:"threshold"`
	Contacts         []struct {
		Email          string  `json:"email"`
		GuardianUserID string  `json:"guardian_user_id"`
		Label          *string `json:"label"`
		ShareIndex     int     `json:"share_index"`
		Shares         []struct {
			DevicePublicKey string `json:"device_public_key"`
			SealedShare     string `json:"sealed_share"`
		} `json:"shares"`
	} `json:"contacts"`
}

func (h *Handler) saveEmergencyContacts(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body saveContactsBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if body.SocialWrappedAMK == "" || len(body.Contacts) == 0 {
		jsonError(w, "social_wrapped_amk and contacts required", http.StatusBadRequest)
		return
	}
	if body.Threshold < 2 || body.Threshold > len(body.Contacts) {
		jsonError(w, "threshold must be between 2 and the number of contacts", http.StatusBadRequest)
		return
	}
	for _, contact := range body.Contacts {
		if contact.GuardianUserID == claims.Subject {
			jsonError(w, "you can't be your own trusted contact", http.StatusBadRequest)
			return
		}
	}

	params := &database.SaveEmergencyContactsParams{
		OwnerID:          claims.Subject,
		SocialWrappedAMK: body.SocialWrappedAMK,
		Threshold:        body.Threshold,
		Total:            len(body.Contacts),
	}
	for _, contact := range body.Contacts {
		guardian := database.GuardianShareParams{
			Email:          contact.Email,
			GuardianUserID: contact.GuardianUserID,
			Label:          contact.Label,
			ShareIndex:     contact.ShareIndex,
		}
		for _, share := range contact.Shares {
			guardian.Shares = append(guardian.Shares, database.SealedDeviceShare{
				DevicePublicKey: share.DevicePublicKey,
				SealedShare:     share.SealedShare,
			})
		}
		params.Contacts = append(params.Contacts, guardian)
	}

	if err := h.store.SaveEmergencyContacts(r.Context(), params); err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listEmergencyContacts(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	contacts, err := h.store.ListEmergencyContacts(r.Context(), claims.Subject)
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	out := make([]map[string]any, 0, len(contacts))
	for _, c := range contacts {
		out = append(out, map[string]any{
			"id":          c.ID,
			"email":       c.Email,
			"label":       c.Label,
			"share_index": c.ShareIndex,
		})
	}
	writeJSON(w, out)
}

func (h *Handler) clearEmergencyContacts(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := h.store.ClearEmergencyContacts(r.Context(), claims.Subject); err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Recovery sessions ────────────────────────────────────────────────────────

func (h *Handler) createRecoverySession(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		RecoveringPublicKey string `json:"recovering_public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RecoveringPublicKey == "" {
		jsonError(w, "recovering_public_key required", http.StatusBadRequest)
		return
	}

	uk, err := h.store.GetUserKeyByUserID(r.Context(), claims.Subject)
	if errors.Is(err, database.ErrNotFound) {
		jsonError(w, "no key material enrolled", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}
	if uk.SocialWrappedAMK == nil || uk.SocialThreshold == nil {
		jsonError(w, "social recovery not configured", http.StatusConflict)
		return
	}

	session, err := h.store.CreateRecoverySession(
		r.Context(), claims.Subject, body.RecoveringPublicKey, *uk.SocialThreshold,
		time.Now().Add(recoverySessionTTL),
	)
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, h.recoverySessionResponse(r, session, uk.SocialWrappedAMK))
}

func (h *Handler) getRecoverySession(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	session, err := h.store.GetRecoverySession(r.Context(), claims.Subject, chi.URLParam(r, "id"))
	if errors.Is(err, database.ErrNotFound) {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	uk, err := h.store.GetUserKeyByUserID(r.Context(), claims.Subject)
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, h.recoverySessionResponse(r, session, uk.SocialWrappedAMK))
}

// recoverySessionResponse bundles the session, the social wrap the new device
// must unwrap, and the shares guardians have submitted so far.
func (h *Handler) recoverySessionResponse(r *http.Request, session *oauth.RecoverySession, socialWrappedAMK *string) map[string]any {
	shares, _ := h.store.ListRecoverySessionShares(r.Context(), recordID(session.ID))
	collected := make([]map[string]any, 0, len(shares))
	for _, s := range shares {
		collected = append(collected, map[string]any{
			"share_index":  s.ShareIndex,
			"sealed_share": s.SealedShare,
		})
	}
	return map[string]any{
		"id":                 recordID(session.ID),
		"status":             session.Status,
		"threshold":          session.Threshold,
		"social_wrapped_amk": socialWrappedAMK,
		"collected":          collected,
		"expires_at":         session.ExpiresAt,
	}
}

func (h *Handler) submitRecoveryShare(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	sessionID := chi.URLParam(r, "id")
	session, err := h.store.GetRecoverySessionByID(r.Context(), sessionID)
	if errors.Is(err, database.ErrNotFound) {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	ownerID := recordID(session.Owner)
	shareIndex, err := h.store.GetGuardianShareIndex(r.Context(), ownerID, claims.Subject)
	if errors.Is(err, database.ErrNotFound) {
		jsonError(w, "not a guardian for this account", http.StatusForbidden)
		return
	}
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	var body struct {
		SealedShare string `json:"sealed_share"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.SealedShare == "" {
		jsonError(w, "sealed_share required", http.StatusBadRequest)
		return
	}

	if err := h.store.SubmitRecoverySessionShare(r.Context(), sessionID, claims.Subject, shareIndex, body.SealedShare); err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) completeRecoverySession(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := h.store.CompleteRecoverySession(r.Context(), claims.Subject, chi.URLParam(r, "id")); err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listRecoveryRequests returns recovery sessions awaiting this guardian, with the
// guardian's own sealed shares so they can open and re-seal one.
func (h *Handler) listRecoveryRequests(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	contacts, err := h.store.ListEmergencyContactsForGuardian(r.Context(), claims.Subject)
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	out := make([]map[string]any, 0)
	for _, contact := range contacts {
		ownerID := recordID(contact.Owner)
		session, err := h.store.GetActiveRecoverySession(r.Context(), ownerID)
		if errors.Is(err, database.ErrNotFound) {
			continue
		}
		if err != nil {
			jsonError(w, "server error", http.StatusInternalServerError)
			return
		}
		submitted, err := h.store.HasSubmittedShare(r.Context(), recordID(session.ID), claims.Subject)
		if err != nil {
			jsonError(w, "server error", http.StatusInternalServerError)
			return
		}
		if submitted {
			continue
		}

		shares, err := h.store.GetRecoverySharesForGuardian(r.Context(), ownerID, claims.Subject)
		if err != nil {
			jsonError(w, "server error", http.StatusInternalServerError)
			return
		}
		sealed := make([]map[string]any, 0, len(shares))
		for _, s := range shares {
			sealed = append(sealed, map[string]any{
				"device_public_key": s.DevicePublicKey,
				"sealed_share":      s.SealedShare,
			})
		}

		ownerEmail, _ := h.store.GetUserEmail(r.Context(), ownerID)
		out = append(out, map[string]any{
			"session_id":            recordID(session.ID),
			"owner_email":           ownerEmail,
			"recovering_public_key": session.RecoveringPublicKey,
			"share_index":           contact.ShareIndex,
			"sealed_shares":         sealed,
			"created_at":            session.CreatedAt,
		})
	}
	writeJSON(w, out)
}
