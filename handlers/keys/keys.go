package keys

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/storage/cache"
	"github.com/neoworks/auth/storage/database"
)

type Handler struct {
	store *database.SurrealStore
	redis *cache.RedisStore
}

func NewHandler(store *database.SurrealStore, redis *cache.RedisStore) *Handler {
	return &Handler{store: store, redis: redis}
}

func (h *Handler) RegisterPublic(r chi.Router) {
	r.Get("/api/v1/auth/key-challenge", h.keyChallenge)
	r.Post("/api/v1/keys/device-invite", h.createDeviceInvite)
	r.Get("/api/v1/keys/device-invite/{token}", h.pollDeviceInvite)
}

func (h *Handler) RegisterAuthenticated(r chi.Router) {
	r.Post("/api/v1/keys", h.registerKeyMaterial)
	r.Post("/api/v1/keys/devices", h.registerDevice)
	r.Get("/api/v1/keys/devices", h.listDevices)
	r.Get("/api/v1/keys/devices/me", h.getMyDevice)
	r.Put("/api/v1/keys/public", h.publishPublicKey)
	r.Get("/api/v1/keys/public", h.lookupPublicKey)
	r.Put("/api/v1/keys/scope-public", h.publishScopeKey)
	r.Get("/api/v1/keys/recovery", h.getRecovery)
	r.Put("/api/v1/keys/recovery", h.rotateRecovery)
	r.Post("/api/v1/keys/device-invite/{token}/approve", h.approveDeviceInvite)
	h.RegisterEmergency(r)
}

// publishPublicKey stores the caller's account public key (X25519, derived in the
// Vault from the AMK) so others can seal file DEKs to it. Idempotent.
func (h *Handler) publishPublicKey(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		PublicKey     string `json:"public_key"`
		Fingerprint   string `json:"fingerprint"`
		SignPublicKey string `json:"sign_public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.PublicKey == "" {
		jsonError(w, "public_key required", http.StatusBadRequest)
		return
	}

	if err := h.store.SetUserPublicKey(r.Context(), claims.Subject, body.PublicKey, body.Fingerprint); err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}
	if body.SignPublicKey != "" {
		if err := h.store.SetUserSignPublicKey(r.Context(), claims.Subject, body.SignPublicKey); err != nil {
			jsonError(w, "server error", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// publishScopeKey stores the caller's PUBLIC key for one encryption scope (the
// Vault derives a distinct keypair per scope from the AMK). Writers seal DEKs to
// it via the directory; the private key is never stored. Idempotent per scope.
func (h *Handler) publishScopeKey(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		Scope     string `json:"scope"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Scope == "" || body.PublicKey == "" {
		jsonError(w, "scope and public_key required", http.StatusBadRequest)
		return
	}

	if err := h.store.SetUserScopeKey(r.Context(), claims.Subject, body.Scope, body.PublicKey); err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// lookupPublicKey is the directory: returns a user's account public key (and bare
// user id) by ?user= or ?email=, so a sender can seal a DEK and address a share.
// The directory is trusted for now — no out-of-band verification of the returned
// key (server MITM is possible). Authenticated to limit enumeration.
func (h *Handler) lookupPublicKey(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	userID := r.URL.Query().Get("user")
	email := r.URL.Query().Get("email")
	scope := r.URL.Query().Get("scope")
	if userID == "" && email == "" {
		jsonError(w, "user or email required", http.StatusBadRequest)
		return
	}

	// With ?scope=, return the per-scope key from the scope directory; otherwise
	// the legacy account key.
	var (
		entry *database.PublicKeyEntry
		err   error
	)
	switch {
	case scope != "" && userID != "":
		entry, err = h.store.GetUserScopeKey(r.Context(), userID, scope)
	case scope != "":
		entry, err = h.store.GetUserScopeKeyByEmail(r.Context(), email, scope)
	case userID != "":
		entry, err = h.store.GetUserPublicKey(r.Context(), userID)
	default:
		entry, err = h.store.GetUserPublicKeyByEmail(r.Context(), email)
	}
	if errors.Is(err, database.ErrNotFound) {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	// The signing key rides along so a sharer can verify wrapped-key and envelope
	// signatures without a second directory call. Empty when not yet published.
	signKey, err := h.store.GetUserSignPublicKey(r.Context(), entry.UserID)
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{
		"user_id":         entry.UserID,
		"public_key":      entry.PublicKey,
		"sign_public_key": signKey,
	})
}

// ── Public ────────────────────────────────────────────────────────────────────

// keyChallenge returns the kdf params and password_wrapped_amk for an email.
// Used by a new device to derive the password key and decrypt the AMK locally.
func (h *Handler) keyChallenge(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		jsonError(w, "missing email", http.StatusBadRequest)
		return
	}

	uk, err := h.store.GetUserKeyByEmail(r.Context(), email)
	if errors.Is(err, database.ErrNotFound) {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	if uk.PasswordWrappedAMK == nil {
		// User has no password-based wrapping; must use device invite or recovery.
		jsonError(w, "no password key enrolled", http.StatusNotFound)
		return
	}

	writeJSON(w, map[string]any{
		"password_wrapped_amk": *uk.PasswordWrappedAMK,
		"argon2_salt":         uk.Argon2Salt,
		"argon2_time":         uk.Argon2Time,
		"argon2_memory":       uk.Argon2Memory,
		"argon2_threads":      uk.Argon2Threads,
		"argon2_keylen":       uk.Argon2Keylen,
	})
}

// createDeviceInvite stores a new device's public key under a short-lived token.
// The new device shows this token (e.g. as a QR) to an existing trusted device.
func (h *Handler) createDeviceInvite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DevicePublicKey string `json:"device_public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.DevicePublicKey == "" {
		jsonError(w, "device_public_key required", http.StatusBadRequest)
		return
	}

	token := uuid.NewString()
	if err := h.redis.CreateDeviceInvite(r.Context(), token, cache.DeviceInvite{
		DevicePublicKey: body.DevicePublicKey,
	}); err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"token": token})
}

// pollDeviceInvite lets the new device check whether the invite was approved.
// Returns 202 while pending; 200 with wrapped_amk once approved.
func (h *Handler) pollDeviceInvite(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")

	result, err := h.redis.GetDeviceInviteResult(r.Context(), token)
	if errors.Is(err, cache.ErrNotFound) {
		// Check the invite still exists (not expired).
		if _, err := h.redis.GetDeviceInvite(r.Context(), token); errors.Is(err, cache.ErrNotFound) {
			jsonError(w, "invite expired or not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"wrapped_amk": result.WrappedAMK})
}

// ── Authenticated ─────────────────────────────────────────────────────────────

// registerKeyMaterial stores the initial key material after account creation.
// Also registers the first device. Called once per account, from the creating device.
func (h *Handler) registerKeyMaterial(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		RecoveryWrappedAMK string  `json:"recovery_wrapped_amk"`
		PasswordWrappedAMK *string `json:"password_wrapped_amk"`
		Argon2Salt         string  `json:"argon2_salt"`
		Argon2Time         int     `json:"argon2_time"`
		Argon2Memory       int     `json:"argon2_memory"`
		Argon2Threads      int     `json:"argon2_threads"`
		Argon2Keylen       int     `json:"argon2_keylen"`
		DevicePublicKey    string  `json:"device_public_key"`
		DeviceWrappedAMK   string  `json:"device_wrapped_amk"`
		DeviceName         *string `json:"device_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if body.RecoveryWrappedAMK == "" || body.Argon2Salt == "" ||
		body.DevicePublicKey == "" || body.DeviceWrappedAMK == "" {
		jsonError(w, "recovery_wrapped_amk, argon2_salt, device_public_key, device_wrapped_amk required", http.StatusBadRequest)
		return
	}

	if _, err := h.store.CreateUserKey(r.Context(), &database.RegisterKeyMaterialParams{
		UserID:             claims.Subject,
		RecoveryWrappedAMK: body.RecoveryWrappedAMK,
		PasswordWrappedAMK: body.PasswordWrappedAMK,
		Argon2Salt:         body.Argon2Salt,
		Argon2Time:         body.Argon2Time,
		Argon2Memory:       body.Argon2Memory,
		Argon2Threads:      body.Argon2Threads,
		Argon2Keylen:       body.Argon2Keylen,
	}); err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	if _, err := h.store.RegisterDevice(r.Context(), &database.RegisterDeviceParams{
		UserID:     claims.Subject,
		PublicKey:  body.DevicePublicKey,
		WrappedAMK: body.DeviceWrappedAMK,
		Name:       body.DeviceName,
	}); err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// registerDevice adds a new device after the client has already unwrapped the AMK
// (via password or recovery) and re-wrapped it for this device's key.
func (h *Handler) registerDevice(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		PublicKey  string  `json:"public_key"`
		WrappedAMK string  `json:"wrapped_amk"`
		Name       *string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.PublicKey == "" || body.WrappedAMK == "" {
		jsonError(w, "public_key and wrapped_amk required", http.StatusBadRequest)
		return
	}

	device, err := h.store.RegisterDevice(r.Context(), &database.RegisterDeviceParams{
		UserID:     claims.Subject,
		PublicKey:  body.PublicKey,
		WrappedAMK: body.WrappedAMK,
		Name:       body.Name,
	})
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, device)
}

func (h *Handler) listDevices(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	devices, err := h.store.ListDevices(r.Context(), claims.Subject)
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, devices)
}

// getMyDevice returns the wrapped_amk for the device identified by ?public_key=.
// Used by a returning browser to unwrap its AMK with its locally-stored private key.
func (h *Handler) getMyDevice(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	publicKey := r.URL.Query().Get("public_key")
	if publicKey == "" {
		jsonError(w, "missing public_key", http.StatusBadRequest)
		return
	}

	device, err := h.store.GetDeviceByPublicKey(r.Context(), claims.Subject, publicKey)
	if errors.Is(err, database.ErrNotFound) {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"wrapped_amk": device.WrappedAMK})
}

// getRecovery returns the recovery_wrapped_amk for the authenticated user.
// The client decrypts it locally using the recovery key derived from HKDF(recovery_secret).
func (h *Handler) getRecovery(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
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

	writeJSON(w, map[string]string{"recovery_wrapped_amk": uk.RecoveryWrappedAMK})
}

// rotateRecovery replaces the recovery_wrapped_amk after a recovery code is consumed.
func (h *Handler) rotateRecovery(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		RecoveryWrappedAMK string `json:"recovery_wrapped_amk"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RecoveryWrappedAMK == "" {
		jsonError(w, "recovery_wrapped_amk required", http.StatusBadRequest)
		return
	}

	if err := h.store.UpdateRecoveryWrappedAMK(r.Context(), claims.Subject, body.RecoveryWrappedAMK); err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// approveDeviceInvite is called by a trusted device to approve a QR invite.
// The trusted device encrypts the AMK to the new device's public key and sends it here.
func (h *Handler) approveDeviceInvite(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimFromContext(r.Context())
	if claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	token := chi.URLParam(r, "token")

	invite, err := h.redis.GetDeviceInvite(r.Context(), token)
	if errors.Is(err, cache.ErrNotFound) {
		jsonError(w, "invite expired or not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	var body struct {
		WrappedAMK string  `json:"wrapped_amk"`
		DeviceName *string `json:"device_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.WrappedAMK == "" {
		jsonError(w, "wrapped_amk required", http.StatusBadRequest)
		return
	}

	if _, err := h.store.RegisterDevice(r.Context(), &database.RegisterDeviceParams{
		UserID:     claims.Subject,
		PublicKey:  invite.DevicePublicKey,
		WrappedAMK: body.WrappedAMK,
		Name:       body.DeviceName,
	}); err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	if err := h.redis.SetDeviceInviteResult(r.Context(), token, cache.DeviceInviteResult{
		WrappedAMK: body.WrappedAMK,
	}); err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
