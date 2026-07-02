package gql

import (
	gql_model "github.com/neoworks/auth/gql/model"
	"github.com/neoworks/auth/storage/database"
)

// storageUsageToModel converts the store's storage breakdown into the GraphQL
// model.
func storageUsageToModel(usage *database.StorageUsage) *gql_model.StorageUsage {
	categories := make([]*gql_model.StorageCategory, 0, len(usage.Categories))
	for _, category := range usage.Categories {
		categories = append(categories, &gql_model.StorageCategory{
			Category: category.Category,
			Bytes:    int(category.Bytes),
		})
	}

	tiers := make([]*gql_model.StorageTier, 0, len(usage.Tiers))
	for _, tier := range usage.Tiers {
		tiers = append(tiers, &gql_model.StorageTier{
			Tier:                tier.Tier,
			Bytes:               int(tier.Bytes),
			UnitPricePerGbMonth: tier.UnitPricePerGBMonth,
			Currency:            tier.Currency,
		})
	}

	history := make([]*gql_model.StoragePoint, 0, len(usage.History))
	for _, point := range usage.History {
		history = append(history, &gql_model.StoragePoint{
			Date:  point.Date,
			Bytes: int(point.Bytes),
		})
	}

	return &gql_model.StorageUsage{
		TotalBytes: int(usage.TotalBytes),
		Categories: categories,
		Tiers:      tiers,
		History:    history,
	}
}
