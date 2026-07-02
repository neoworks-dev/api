// Package mollie exposes the Mollie payment webhook. Mollie calls it
// server-to-server with the id of a payment whose status changed; we fetch the
// payment (the id alone is not trusted) and reflect its result onto the
// organization's mandate status.
package mollie

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/mollie"
	"github.com/neoworks/auth/storage/database"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

type Handler struct {
	store  *database.SurrealStore
	client mollie.Client
}

func NewHandler(store *database.SurrealStore, client mollie.Client) *Handler {
	return &Handler{store: store, client: client}
}

func (h *Handler) RegisterPublic(r chi.Router) {
	r.Post("/webhooks/mollie", h.handleWebhook)
}

// mandateStatusFor maps a Mollie payment status to the org mandate status we
// persist. A paid first payment means a reusable mandate now exists.
func mandateStatusFor(paymentStatus string) string {
	switch paymentStatus {
	case "paid":
		return "valid"
	case "failed", "canceled", "expired":
		return "invalid"
	default:
		return "pending"
	}
}

func (h *Handler) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	paymentID := r.PostFormValue("id")
	if paymentID == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	payment, err := h.client.GetPayment(r.Context(), paymentID)
	if err != nil {
		// Ask Mollie to retry later rather than dropping the event.
		slog.Error("mollie webhook: fetch payment", "error", err, "payment", paymentID)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	if payment.OrganizationID == "" {
		// Not one of ours (or missing metadata); acknowledge so Mollie stops retrying.
		w.WriteHeader(http.StatusOK)
		return
	}

	status := mandateStatusFor(payment.Status)
	orgRef := models.NewRecordID("organization", payment.OrganizationID)
	if _, err := surrealdb.Query[[]any](r.Context(), h.store.DB,
		"UPDATE $org SET mollie_mandate_status = $status WHERE deleted_at = NONE",
		map[string]any{"org": orgRef, "status": status},
	); err != nil {
		slog.Error("mollie webhook: update org", "error", err, "org", payment.OrganizationID)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	slog.Info("mollie webhook processed", "org", payment.OrganizationID, "payment", paymentID, "mandate_status", status)
	w.WriteHeader(http.StatusOK)
}
