package gql

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/neoworks/auth/config"
	gql_model "github.com/neoworks/auth/gql/model"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/mollie"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// setupPaymentAmount is the small verification charge for the sequenceType=first
// payment that captures a reusable mandate. Test-mode payments move no real money.
var setupPaymentAmount = mollie.Money{Currency: "EUR", Value: "0.01"}

// loadOrganization reads a single active organization by id.
func loadOrganization(ctx context.Context, db *surrealdb.DB, orgRef models.RecordID) (*dbOrganization, error) {
	results, err := surrealdb.Query[[]dbOrganization](ctx, db,
		"SELECT * FROM $org WHERE deleted_at = NONE",
		map[string]any{"org": orgRef},
	)
	if err != nil {
		return nil, fmt.Errorf("load organization: %w", err)
	}
	return firstOrganization(results), nil
}

// startOrgPayment creates (or reuses) the org's Mollie customer, starts a first
// payment to capture a mandate, and returns the hosted checkout URL.
func (r *mutationResolver) startOrgPayment(ctx context.Context, organizationID string) (*gql_model.PaymentSetup, error) {
	claim := middleware.ClaimFromContext(ctx)
	if claim == nil {
		return nil, errUnauthenticated
	}
	orgRef := models.NewRecordID("organization", organizationID)
	if !r.callerCanAdminOrg(ctx, claim.Subject, orgRef) {
		return nil, Public("forbidden: caller cannot set up billing for this organization")
	}
	if !r.mollie.Enabled() {
		return nil, Public("payment provider is not configured")
	}

	org, err := loadOrganization(ctx, r.store.DB, orgRef)
	if err != nil {
		return nil, err
	}
	if org == nil {
		return nil, Public("organization not found")
	}

	customerID, err := r.ensureMollieCustomer(ctx, orgRef, org)
	if err != nil {
		return nil, fmt.Errorf("ensure mollie customer: %w", err)
	}

	payment, err := r.mollie.CreateFirstPayment(ctx, mollie.FirstPaymentInput{
		CustomerID:     customerID,
		Amount:         setupPaymentAmount,
		Description:    "Payment method setup for " + org.Name,
		RedirectURL:    billingReturnURL(organizationID),
		WebhookURL:     os.Getenv("MOLLIE_WEBHOOK_URL"),
		OrganizationID: organizationID,
	})
	if err != nil {
		return nil, fmt.Errorf("create first payment: %w", err)
	}

	// Mark the org as awaiting confirmation; the webhook flips it to valid/invalid.
	if _, err := surrealdb.Query[[]any](ctx, r.store.DB,
		"UPDATE $org SET mollie_mandate_status = $status WHERE deleted_at = NONE",
		map[string]any{"org": orgRef, "status": "pending"},
	); err != nil {
		return nil, fmt.Errorf("mark payment pending: %w", err)
	}

	return &gql_model.PaymentSetup{CheckoutURL: payment.CheckoutURL}, nil
}

// ensureMollieCustomer returns the org's existing Mollie customer id or creates
// one and persists it.
func (r *mutationResolver) ensureMollieCustomer(ctx context.Context, orgRef models.RecordID, org *dbOrganization) (string, error) {
	if org.MollieCustomerID != nil && *org.MollieCustomerID != "" {
		return *org.MollieCustomerID, nil
	}

	email := ""
	if org.BillingEmail != nil {
		email = *org.BillingEmail
	}
	customerID, err := r.mollie.CreateCustomer(ctx, org.Name, email)
	if err != nil {
		return "", err
	}

	if _, err := surrealdb.Query[[]any](ctx, r.store.DB,
		"UPDATE $org SET mollie_customer_id = $customer WHERE deleted_at = NONE",
		map[string]any{"org": orgRef, "customer": customerID},
	); err != nil {
		return "", fmt.Errorf("store customer id: %w", err)
	}
	return customerID, nil
}

// loadOrgBillingStatus reports an org's mandate status. Caller must be a member.
func (r *queryResolver) loadOrgBillingStatus(ctx context.Context, organizationID string) (*gql_model.OrgBillingStatus, error) {
	claim := middleware.ClaimFromContext(ctx)
	if claim == nil {
		return nil, errUnauthenticated
	}
	orgRef := models.NewRecordID("organization", organizationID)
	if !r.callerIsMember(ctx, claim.Subject, orgRef) {
		return nil, Public("forbidden: caller is not a member of this organization")
	}

	org, err := loadOrganization(ctx, r.store.DB, orgRef)
	if err != nil {
		return nil, err
	}
	if org == nil {
		return nil, Public("organization not found")
	}

	status := "none"
	if org.MollieMandateStatus != nil && *org.MollieMandateStatus != "" {
		status = *org.MollieMandateStatus
	}
	return &gql_model.OrgBillingStatus{
		Status:           status,
		HasPaymentMethod: status == "valid",
	}, nil
}

// billingReturnURL is where Mollie sends the user after checkout — back to the
// onboarding billing step, which re-checks status on return. Mirrors the invite
// link's base resolution: APP_WEB_URL, falling back to the derived service URL.
func billingReturnURL(organizationID string) string {
	base := os.Getenv("APP_WEB_URL")
	if base == "" {
		base = config.ServiceURL("")
	}
	base = strings.TrimRight(base, "/")
	return fmt.Sprintf("%s/dashboard/organizations/new/%s/billing?payment=return", base, organizationID)
}
