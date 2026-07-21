package keys

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/storage/database"
)

// RegisterChat wires the X3DH prekey keystore. Persistent chat key material lives
// here alongside the device/key registry it extends; ephemeral message forwarding
// lives in the separate chat-relay service.
func (h *Handler) RegisterChat(r chi.Router) {
	r.Post("/api/v1/chat/prekeys", h.publishChatPrekeys)
	r.Get("/api/v1/chat/prekeys/bundle", h.getChatPrekeyBundle)
	r.Get("/api/v1/chat/prekeys/count", h.getChatPrekeyCount)
}

// publishChatPrekeys stores a device's chat identity, its current signed prekey,
// and a batch of one-time prekeys. The device is addressed by its device public key
// (the same handle used to fetch a wrapped AMK); the caller must own it.
func (h *Handler) publishChatPrekeys(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		DevicePublicKey string                   `json:"device_public_key"`
		IdentityKey     string                   `json:"identity_key"`
		SigningKey      string                   `json:"signing_key"`
		SignedPrekey    database.SignedPrekey    `json:"signed_prekey"`
		OneTimePrekeys  []database.OneTimePrekey `json:"one_time_prekeys"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if body.DevicePublicKey == "" || body.IdentityKey == "" || body.SigningKey == "" || body.SignedPrekey.PublicKey == "" {
		jsonError(w, "device_public_key, identity_key, signing_key, signed_prekey required", http.StatusBadRequest)
		return
	}

	deviceID, err := h.resolveOwnDeviceID(r, claims.Subject, body.DevicePublicKey)
	if err != nil {
		writeDeviceError(w, err)
		return
	}

	if err := h.store.SetDeviceChatIdentity(r.Context(), claims.Subject, body.DevicePublicKey, body.IdentityKey, body.SigningKey); err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}
	if err := h.store.PublishSignedPrekey(r.Context(), deviceID, body.SignedPrekey); err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}
	if err := h.store.AddOneTimePrekeys(r.Context(), deviceID, body.OneTimePrekeys); err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// getChatPrekeyBundle returns one X3DH bundle per device of the target user
// (?user= or ?email=). Each call pops a one-time prekey per device.
func (h *Handler) getChatPrekeyBundle(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	targetUserID, err := h.resolveTargetUser(r)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			jsonError(w, "not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, errMissingTarget) {
			jsonError(w, "user or email required", http.StatusBadRequest)
			return
		}
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	bundles, err := h.store.GetPrekeyBundles(r.Context(), targetUserID)
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{
		"user_id": targetUserID,
		"devices": bundles,
	})
}

// getChatPrekeyCount reports the caller's remaining one-time prekeys for one of
// their own devices (?device_public_key=), driving client-side replenishment.
func (h *Handler) getChatPrekeyCount(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	devicePublicKey := r.URL.Query().Get("device_public_key")
	if devicePublicKey == "" {
		jsonError(w, "device_public_key required", http.StatusBadRequest)
		return
	}

	deviceID, err := h.resolveOwnDeviceID(r, claims.Subject, devicePublicKey)
	if err != nil {
		writeDeviceError(w, err)
		return
	}

	count, err := h.store.CountOneTimePrekeys(r.Context(), deviceID)
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]int{"count": count})
}

var errMissingTarget = errors.New("missing target")

func (h *Handler) resolveTargetUser(r *http.Request) (string, error) {
	if userID := r.URL.Query().Get("user"); userID != "" {
		return userID, nil
	}
	email := r.URL.Query().Get("email")
	if email == "" {
		return "", errMissingTarget
	}
	entry, err := h.store.GetUserPublicKeyByEmail(r.Context(), email)
	if err != nil {
		return "", err
	}
	return entry.UserID, nil
}

// resolveOwnDeviceID looks up the bare device id for a device the caller owns,
// addressed by its public key.
func (h *Handler) resolveOwnDeviceID(r *http.Request, userID, devicePublicKey string) (string, error) {
	device, err := h.store.GetDeviceByPublicKey(r.Context(), userID, devicePublicKey)
	if err != nil {
		return "", err
	}
	if device.ID == nil {
		return "", database.ErrNotFound
	}
	return fmt.Sprintf("%v", device.ID.ID), nil
}

func writeDeviceError(w http.ResponseWriter, err error) {
	if errors.Is(err, database.ErrNotFound) {
		jsonError(w, "device not found", http.StatusNotFound)
		return
	}
	jsonError(w, "server error", http.StatusInternalServerError)
}
