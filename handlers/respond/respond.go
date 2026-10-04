// Package respond holds the JSON response and request helpers shared by the
// REST handlers.
package respond

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/neoworks/auth/storage/database"
)

// JSON writes value as the response body. HTML escaping is off so stored
// ciphertext and JSON blobs come back byte for byte.
func JSON(w http.ResponseWriter, status int, value any) {
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		slog.Error("encode response", "error", err)
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body.Bytes())
}

// Error writes {"error": code, "message": message}.
func Error(w http.ResponseWriter, status int, code, message string) {
	JSON(w, status, map[string]string{"error": code, "message": message})
}

// Decode reads a JSON request body of at most maxBytes into target and reports
// whether the handler should continue.
func Decode(w http.ResponseWriter, r *http.Request, target any, maxBytes int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		Error(w, http.StatusBadRequest, "invalid_body", "request body is not valid JSON of the expected shape")
		return false
	}
	return true
}

// StoreError maps a storage error to an HTTP response. Unrecognized errors are
// logged and answered with a generic 500 so internals never reach the client.
func StoreError(w http.ResponseWriter, operation string, err error) {
	var purged *database.PurgedError
	switch {
	case errors.As(err, &purged):
		JSON(w, http.StatusGone, map[string]any{"error": "cursor_purged", "purgeHorizon": purged.Horizon})
	case errors.Is(err, database.ErrNotFound):
		Error(w, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, database.ErrForbidden):
		Error(w, http.StatusForbidden, "forbidden", "forbidden")
	case errors.Is(err, database.ErrStaleEpoch):
		Error(w, http.StatusConflict, "stale_epoch", "the node key epoch has changed; re-seal to the current epoch")
	case errors.Is(err, database.ErrUnknownPrincipal):
		Error(w, http.StatusUnprocessableEntity, "unknown_principal", "the principal does not exist or was revoked")
	case errors.Is(err, database.ErrInvalidInput):
		Error(w, http.StatusBadRequest, "invalid_request", err.Error())
	default:
		slog.Error("request failed", "operation", operation, "error", err)
		Error(w, http.StatusInternalServerError, "server_error", "internal server error")
	}
}
