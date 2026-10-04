// Package nodes serves the encrypted node tree: sync, history, sharing,
// delegation certificates and link shares. The server enforces roles and never
// interprets ciphertext, wrapped keys or signatures.
package nodes

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/storage/database"
)

const (
	maxPushBatch     = 100
	maxPushBodyBytes = 32 << 20
	maxGrantBody     = 64 << 10
)

type Handler struct {
	store *database.SurrealStore
}

func NewHandler(store *database.SurrealStore) *Handler {
	return &Handler{store: store}
}

// RegisterAuthenticated mounts the endpoints that need a verified principal.
func (h *Handler) RegisterAuthenticated(router chi.Router) {
	router.Post("/api/v1/nodes/push", h.push)
	router.Get("/api/v1/nodes/pull", h.pull)
	router.Get("/api/v1/nodes/{id}/versions", h.versions)
	router.Post("/api/v1/nodes/{id}/grants", h.createGrant)
	router.Post("/api/v1/nodes/{id}/grants/revoke", h.revokeGrant)
	router.Get("/api/v1/nodes/{id}/access-log", h.accessLog)
	router.Get("/api/v1/certificates/{certId}", h.certificate)
	router.Post("/api/v1/links", h.createLink)
	router.Delete("/api/v1/links/{id}", h.revokeLink)
}

// RegisterPublic mounts the link endpoints, which anyone holding the link may call.
func (h *Handler) RegisterPublic(router chi.Router) {
	router.Get("/api/v1/links/{id}/pull", h.pullLink)
}

func principalOf(w http.ResponseWriter, r *http.Request) (access.Principal, bool) {
	principal, ok := middleware.PrincipalFromContext(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "invalid_token", "no principal")
	}
	return principal, ok
}

type pushRequest struct {
	Nodes []database.Node `json:"nodes"`
}

// push writes a batch of nodes in order, one transaction per node, so a
// conflict on one does not fail the others. The whole batch is rejected up
// front when any node is malformed.
func (h *Handler) push(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalOf(w, r)
	if !ok {
		return
	}
	var request pushRequest
	if !respond.Decode(w, r, &request, maxPushBodyBytes) {
		return
	}
	validated, ok := validateBatch(w, request.Nodes, principal)
	if !ok {
		return
	}

	results := make([]database.PushOutcome, 0, len(validated))
	for _, node := range validated {
		outcome, err := h.store.PushNode(r.Context(), principal, node)
		if err != nil {
			respond.StoreError(w, "push", err)
			return
		}
		results = append(results, *outcome)
	}
	respond.JSON(w, http.StatusOK, map[string]any{"results": results})
}

func validateBatch(w http.ResponseWriter, nodes []database.Node, principal access.Principal) ([]*database.ValidatedNode, bool) {
	if len(nodes) == 0 || len(nodes) > maxPushBatch {
		respond.Error(w, http.StatusBadRequest, "invalid_request", "push between 1 and "+strconv.Itoa(maxPushBatch)+" nodes")
		return nil, false
	}
	validated := make([]*database.ValidatedNode, 0, len(nodes))
	for index, node := range nodes {
		checked, err := database.ValidateNodeInput(node, principal)
		if err != nil {
			writeInvalidNode(w, index, err)
			return nil, false
		}
		validated = append(validated, checked)
	}
	return validated, true
}

func writeInvalidNode(w http.ResponseWriter, index int, err error) {
	body := map[string]any{"error": "invalid_node", "index": index, "message": err.Error()}
	respond.JSON(w, http.StatusBadRequest, body)
}

func (h *Handler) pull(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalOf(w, r)
	if !ok {
		return
	}
	cursor, limit, ok := pageParameters(w, r)
	if !ok {
		return
	}
	page, err := h.store.Pull(r.Context(), principal, cursor, limit)
	if err != nil {
		respond.StoreError(w, "pull", err)
		return
	}
	respond.JSON(w, http.StatusOK, page)
}

func pageParameters(w http.ResponseWriter, r *http.Request) (int64, int, bool) {
	cursor, err := parseNonNegative(r.URL.Query().Get("cursor"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid_request", "cursor must be a non-negative integer")
		return 0, 0, false
	}
	limit, err := parseNonNegative(r.URL.Query().Get("limit"))
	if err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid_request", "limit must be a non-negative integer")
		return 0, 0, false
	}
	return cursor, int(limit), true
}

func parseNonNegative(raw string) (int64, error) {
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		return 0, strconv.ErrSyntax
	}
	return value, nil
}

func (h *Handler) versions(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalOf(w, r)
	if !ok {
		return
	}
	versions, err := h.store.ListNodeVersions(r.Context(), principal, chi.URLParam(r, "id"))
	if err != nil {
		respond.StoreError(w, "versions", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"versions": versions})
}

func (h *Handler) certificate(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalOf(w, r)
	if !ok {
		return
	}
	certificate, err := h.store.CertificateForPrincipal(r.Context(), principal, chi.URLParam(r, "certId"))
	if err != nil {
		respond.StoreError(w, "certificate", err)
		return
	}
	respond.JSON(w, http.StatusOK, certificate)
}
