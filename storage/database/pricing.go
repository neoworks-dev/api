package database

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// pricingJSON is the rate card bundled with the binary. Prices are locked into
// each billing event at event time, so changing this file only affects events
// created afterwards.
//
//go:embed pricing.json
var pricingJSON []byte

// Pricing is the rate card: currency plus per-unit prices for each billable
// resource. Storage prices are per GB-month for the matching tier.
type Pricing struct {
	Currency                 string  `json:"currency"`
	StorageHotPerGBMonth     float64 `json:"storage_hot_per_gb_month"`
	StorageColdPerGBMonth    float64 `json:"storage_cold_per_gb_month"`
	StorageArchivePerGBMonth float64 `json:"storage_archive_per_gb_month"`
	ComputePerSecond         float64 `json:"compute_per_second"`
	APIPerCall               float64 `json:"api_per_call"`
	ProvisioningDatabase     float64 `json:"provisioning_database"`
}

// StoragePricePerGBMonth returns the unit price for a storage tier
// ("hot" | "cold" | "archive"); unknown tiers fall back to the hot price.
func (p Pricing) StoragePricePerGBMonth(tier string) float64 {
	switch tier {
	case "cold":
		return p.StorageColdPerGBMonth
	case "archive":
		return p.StorageArchivePerGBMonth
	default:
		return p.StorageHotPerGBMonth
	}
}

// loadPricing parses the embedded rate card. It fails loudly at startup if the
// bundled file is malformed — a missing rate card is a build/config error.
func loadPricing() (Pricing, error) {
	var p Pricing
	if err := json.Unmarshal(pricingJSON, &p); err != nil {
		return Pricing{}, fmt.Errorf("parse pricing.json: %w", err)
	}
	if p.Currency == "" {
		return Pricing{}, fmt.Errorf("pricing.json: currency is required")
	}
	return p, nil
}
