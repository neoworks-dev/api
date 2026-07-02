package database

import (
	"context"
	"time"

	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

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
	_, err := surrealdb.Query[[]any](ctx, s.DB, `
		CREATE billing_provisioning_event SET
			billed_to     = $billed_to,
			source_client = $source_client,
			resource      = $resource,
			units         = $units,
			unit_price    = $unit_price,
			currency      = $currency,
			ref           = $ref,
			occurred_at   = $occurred_at
	`, map[string]any{
		"billed_to":     p.BilledTo,
		"source_client": p.SourceClient,
		"resource":      p.Resource,
		"units":         p.Units,
		"unit_price":    p.UnitPrice,
		"currency":      p.Currency,
		"ref":           p.Ref,
		"occurred_at":   time.Now(),
	})
	return err
}

func (s *SurrealStore) CreateComputeBillingEvent(ctx context.Context, p BillingEventParams) error {
	_, err := surrealdb.Query[[]any](ctx, s.DB, `
		CREATE billing_compute_event SET
			billed_to     = $billed_to,
			source_client = $source_client,
			units         = $units,
			unit_price    = $unit_price,
			currency      = $currency,
			ref           = $ref,
			occurred_at   = $occurred_at
	`, map[string]any{
		"billed_to":     p.BilledTo,
		"source_client": p.SourceClient,
		"units":         p.Units,
		"unit_price":    p.UnitPrice,
		"currency":      p.Currency,
		"ref":           p.Ref,
		"occurred_at":   time.Now(),
	})
	return err
}

func (s *SurrealStore) CreateAPIBillingEvent(ctx context.Context, p BillingEventParams) error {
	_, err := surrealdb.Query[[]any](ctx, s.DB, `
		CREATE billing_api_event SET
			billed_to     = $billed_to,
			source_client = $source_client,
			units         = $units,
			unit_price    = $unit_price,
			currency      = $currency,
			ref           = $ref,
			occurred_at   = $occurred_at
	`, map[string]any{
		"billed_to":     p.BilledTo,
		"source_client": p.SourceClient,
		"units":         p.Units,
		"unit_price":    p.UnitPrice,
		"currency":      p.Currency,
		"ref":           p.Ref,
		"occurred_at":   time.Now(),
	})
	return err
}
