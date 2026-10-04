package database

import (
	"context"
	"fmt"

	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// Asset is a stored object served by the assets listener (public or owner-private
// plaintext), distinct from encrypted node blobs.
type Asset struct {
	ID         *models.RecordID `json:"id,omitempty"`
	StorageKey string           `json:"storage_key"`
	Mime       string           `json:"mime"`
	Size       int              `json:"size"`
	Visibility string           `json:"visibility"`
	Owner      *models.RecordID `json:"owner,omitempty"`
}

// CreateAssetParams describes a new asset upload.
type CreateAssetParams struct {
	StorageKey string
	Mime       string
	Size       int
	Visibility string
	UserID     string
}

func (s *SurrealStore) CreateAsset(ctx context.Context, params CreateAssetParams) (*Asset, error) {
	asset, err := queryFirst[Asset](ctx, s.DB, `
		CREATE asset SET
			storage_key = $storage_key,
			mime        = $mime,
			size        = $size,
			visibility  = $visibility,
			owner       = $owner`,
		map[string]any{
			"storage_key": params.StorageKey,
			"mime":        params.Mime,
			"size":        params.Size,
			"visibility":  params.Visibility,
			"owner":       models.NewRecordID("user", params.UserID),
		})
	if err != nil {
		return nil, fmt.Errorf("create asset: %w", err)
	}
	return asset, nil
}
