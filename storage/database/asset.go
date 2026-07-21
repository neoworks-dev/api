package database

import (
	"context"
	"fmt"
	"strings"

	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// Asset is a stored object served by the assets service (public/cached, plaintext
// — distinct from the encrypted owner-only file surface).
type Asset struct {
	ID           *models.RecordID `json:"id,omitempty"`
	StorageKey   string           `json:"storage_key"`
	Mime         string           `json:"mime"`
	Size         int              `json:"size"`
	Visibility   string           `json:"visibility"`
	Owner        *models.RecordID `json:"owner,omitempty"`
	Organization *models.RecordID `json:"organization,omitempty"`
}

// CreateAssetParams describes a new asset upload. ClientID is the uploading OAuth
// client; its owning organization is billed for the storage (clients are always
// org-owned), mirroring how client databases route usage to the org.
type CreateAssetParams struct {
	StorageKey string
	Mime       string
	Size       int
	Visibility string
	UserID     string
	ClientID   string
}

// clientOrganization returns the owning organization of a client, or nil.
func (s *SurrealStore) clientOrganization(ctx context.Context, clientID string) *models.RecordID {
	if clientID == "" {
		return nil
	}
	results, err := surrealdb.Query[[]*models.RecordID](ctx, s.DB,
		"SELECT VALUE organization FROM client WHERE id = $client LIMIT 1",
		map[string]any{"client": models.NewRecordID("client", clientID)})
	if err != nil {
		return nil
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0]
		}
	}
	return nil
}

// CreateAsset persists an asset row and opens a storage billing period for it, in
// one transaction. Usage bills the uploading client's organization (source_client
// records which client incurred it); without a resolvable org it falls back to the
// uploading user. The price + currency come from the rate card and lock into the row.
func (s *SurrealStore) CreateAsset(ctx context.Context, p CreateAssetParams) (*Asset, error) {
	const tier = "hot"
	orgRef := s.clientOrganization(ctx, p.ClientID)

	assetAssigns := []string{
		"storage_key = $storage_key",
		"mime = $mime",
		"size = $size",
		"visibility = $visibility",
		"owner = $owner",
	}
	billAssigns := []string{
		"billed_to = $billed_to",
		"tier = $tier",
		"size_bytes = $size",
		"unit_price = $unit_price",
		"currency = $currency",
		"ref = $asset.id",
		"start_time = time::now()",
	}
	params := map[string]any{
		"storage_key": p.StorageKey,
		"mime":        p.Mime,
		"size":        p.Size,
		"visibility":  p.Visibility,
		"owner":       models.NewRecordID("user", p.UserID),
		"tier":        tier,
		"unit_price":  s.pricing.StoragePricePerGBMonth(tier),
		"currency":    s.pricing.Currency,
	}

	// Org-owned usage bills the organization; otherwise the uploading user.
	if orgRef != nil {
		assetAssigns = append(assetAssigns, "organization = $org")
		billAssigns = append(billAssigns, "source_client = $client")
		params["org"] = *orgRef
		params["client"] = models.NewRecordID("client", p.ClientID)
		params["billed_to"] = *orgRef
	} else {
		params["billed_to"] = models.NewRecordID("user", p.UserID)
	}

	query := fmt.Sprintf(`
		BEGIN TRANSACTION;
		LET $asset = (CREATE asset SET %s)[0];
		CREATE billing_storage_period SET %s;
		RETURN [$asset];
		COMMIT TRANSACTION;
	`, strings.Join(assetAssigns, ", "), strings.Join(billAssigns, ", "))

	results, err := surrealdb.Query[[]Asset](ctx, s.DB, query, params)
	if err != nil {
		return nil, fmt.Errorf("create asset: %w", err)
	}
	return lastResult(*results, "create asset: no result returned")
}
