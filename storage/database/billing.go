package database

import (
	"context"
	"strings"
	"time"

	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// appendOptionalRefs adds the optional source_client and ref assignments only when
// present. Absent option<record> fields must be omitted so they default to NONE;
// setting them to a nil pointer sends SQL NULL, which the schema rejects.
func appendOptionalRefs(assignments []string, params map[string]any, sourceClient, ref *models.RecordID) []string {
	if sourceClient != nil {
		assignments = append(assignments, "source_client = $source_client")
		params["source_client"] = sourceClient
	}
	if ref != nil {
		assignments = append(assignments, "ref = $ref")
		params["ref"] = ref
	}
	return assignments
}

type BillingEventParams struct {
	// BilledTo is the billed party: a user (personal usage) or an organization (client usage).
	BilledTo models.RecordID
	// SourceClient is the client that generated org usage; nil for personal user usage.
	SourceClient *models.RecordID
	Units        float64
	UnitPrice    float64
	Currency     string
	Ref          *models.RecordID // causal record, optional
}

type ProvisioningBillingEventParams struct {
	BillingEventParams
	Resource string // e.g. "database"
}

func (s *SurrealStore) CreateProvisioningBillingEvent(ctx context.Context, p ProvisioningBillingEventParams) error {
	assignments := []string{
		"billed_to = $billed_to",
		"resource = $resource",
		"units = $units",
		"unit_price = $unit_price",
		"currency = $currency",
		"occurred_at = $occurred_at",
	}
	params := map[string]any{
		"billed_to":   p.BilledTo,
		"resource":    p.Resource,
		"units":       p.Units,
		"unit_price":  p.UnitPrice,
		"currency":    p.Currency,
		"occurred_at": time.Now(),
	}
	assignments = appendOptionalRefs(assignments, params, p.SourceClient, p.Ref)
	_, err := surrealdb.Query[[]any](ctx, s.DB,
		"CREATE billing_provisioning_event SET "+strings.Join(assignments, ", "), params)
	return err
}

func (s *SurrealStore) CreateComputeBillingEvent(ctx context.Context, p BillingEventParams) error {
	return s.createBillingEvent(ctx, "billing_compute_event", p)
}

func (s *SurrealStore) CreateAPIBillingEvent(ctx context.Context, p BillingEventParams) error {
	return s.createBillingEvent(ctx, "billing_api_event", p)
}

// createBillingEvent writes a compute/api usage event, omitting the optional
// source_client and ref fields when unset (see appendOptionalRefs).
func (s *SurrealStore) createBillingEvent(ctx context.Context, table string, p BillingEventParams) error {
	assignments := []string{
		"billed_to = $billed_to",
		"units = $units",
		"unit_price = $unit_price",
		"currency = $currency",
		"occurred_at = $occurred_at",
	}
	params := map[string]any{
		"billed_to":   p.BilledTo,
		"units":       p.Units,
		"unit_price":  p.UnitPrice,
		"currency":    p.Currency,
		"occurred_at": time.Now(),
	}
	assignments = appendOptionalRefs(assignments, params, p.SourceClient, p.Ref)
	_, err := surrealdb.Query[[]any](ctx, s.DB,
		"CREATE "+table+" SET "+strings.Join(assignments, ", "), params)
	return err
}
