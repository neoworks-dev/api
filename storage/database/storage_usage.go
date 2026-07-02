package database

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// storageUsageTTL is how long a computed StorageUsage breakdown is served from
// the in-memory cache before being recomputed.
const storageUsageTTL = 15 * time.Minute

// StorageCategory is logical (pre-dedup) bytes for a coarse file category.
type StorageCategory struct {
	Category string
	Bytes    int64
}

// StorageTier is currently-stored bytes for a billing tier, with the live rate.
type StorageTier struct {
	Tier                string
	Bytes               int64
	UnitPricePerGBMonth float64
	Currency            string
}

// StoragePoint is the cumulative stored bytes on a single day.
type StoragePoint struct {
	Date  string
	Bytes int64
}

// StorageUsage is the full storage breakdown for one user.
type StorageUsage struct {
	TotalBytes int64
	Categories []StorageCategory
	Tiers      []StorageTier
	History    []StoragePoint
}

// storageCategoryOrder fixes the category set and display order; every breakdown
// emits exactly these, with zero bytes when a category is empty.
var storageCategoryOrder = []string{"photos", "videos", "documents", "other"}

// storageTierOrder fixes the tier set and display order, matching the values the
// billing pipeline writes to billing_storage_period.tier.
var storageTierOrder = []string{"hot", "cold", "archive"}

type storageUsageCacheEntry struct {
	usage     *StorageUsage
	expiresAt time.Time
}

// storageUsageCache is a per-user TTL cache for the storage breakdown. The
// aggregate scans the user's whole billing history, so it is worth not
// recomputing on every dashboard load.
type storageUsageCache struct {
	mu      sync.Mutex
	entries map[string]storageUsageCacheEntry
}

func newStorageUsageCache() *storageUsageCache {
	return &storageUsageCache{entries: make(map[string]storageUsageCacheEntry)}
}

func (c *storageUsageCache) get(userID string, now time.Time) (*StorageUsage, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[userID]
	if !ok || now.After(entry.expiresAt) {
		return nil, false
	}
	return entry.usage, true
}

func (c *storageUsageCache) set(userID string, usage *StorageUsage, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[userID] = storageUsageCacheEntry{usage: usage, expiresAt: now.Add(storageUsageTTL)}
}

// StorageUsage returns the storage breakdown for the user, serving a cached
// result when one is still fresh (see storageUsageTTL).
func (s *SurrealStore) StorageUsage(ctx context.Context, userID string) (*StorageUsage, error) {
	now := time.Now()
	if cached, ok := s.storageCache.get(userID, now); ok {
		return cached, nil
	}

	usage, err := s.computeStorageUsage(ctx, userID)
	if err != nil {
		return nil, err
	}

	s.storageCache.set(userID, usage, now)
	return usage, nil
}

func (s *SurrealStore) computeStorageUsage(ctx context.Context, userID string) (*StorageUsage, error) {
	user := models.NewRecordID("user", userID)

	total, err := s.storageTotalBytes(ctx, user)
	if err != nil {
		return nil, err
	}
	categories, err := s.storageCategories(ctx, user)
	if err != nil {
		return nil, err
	}
	tiers, err := s.storageTiers(ctx, user)
	if err != nil {
		return nil, err
	}
	history, err := s.storageHistory(ctx, user, time.Now())
	if err != nil {
		return nil, err
	}

	return &StorageUsage{
		TotalBytes: total,
		Categories: categories,
		Tiers:      tiers,
		History:    history,
	}, nil
}

// storageTotalBytes reads the authoritative, chunk-deduplicated total kept on
// the user record.
func (s *SurrealStore) storageTotalBytes(ctx context.Context, user models.RecordID) (int64, error) {
	results, err := surrealdb.Query[[]struct {
		StorageUsedBytes int64 `json:"storage_used_bytes"`
	}](
		ctx, s.DB,
		"SELECT storage_used_bytes FROM $user",
		map[string]any{"user": user},
	)
	if err != nil {
		return 0, fmt.Errorf("storage total: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0].StorageUsedBytes, nil
		}
	}
	return 0, nil
}

// storageCategories sums logical media size grouped by mime type, then buckets
// the mime types into coarse display categories.
func (s *SurrealStore) storageCategories(ctx context.Context, user models.RecordID) ([]StorageCategory, error) {
	results, err := surrealdb.Query[[]struct {
		MimeType string `json:"mime_type"`
		Bytes    int64  `json:"bytes"`
	}](
		ctx, s.DB,
		"SELECT mime_type, math::sum(size) AS bytes FROM media WHERE user = $user GROUP BY mime_type",
		map[string]any{"user": user},
	)
	if err != nil {
		return nil, fmt.Errorf("storage categories: %w", err)
	}

	byCategory := map[string]int64{}
	for _, qr := range *results {
		for _, row := range qr.Result {
			byCategory[categoryForMime(row.MimeType)] += row.Bytes
		}
	}

	return orderedCategories(byCategory), nil
}

// categoryForMime maps a mime type to one of the coarse display categories.
func categoryForMime(mimeType string) string {
	if strings.HasPrefix(mimeType, "image/") {
		return "photos"
	}
	if strings.HasPrefix(mimeType, "video/") {
		return "videos"
	}
	if isDocumentMime(mimeType) {
		return "documents"
	}
	return "other"
}

func isDocumentMime(mimeType string) bool {
	if strings.HasPrefix(mimeType, "text/") {
		return true
	}
	documentMimes := []string{
		"application/pdf",
		"application/msword",
		"application/vnd.openxmlformats-officedocument",
		"application/vnd.ms-excel",
		"application/vnd.ms-powerpoint",
		"application/vnd.oasis.opendocument",
		"application/rtf",
	}
	for _, prefix := range documentMimes {
		if strings.HasPrefix(mimeType, prefix) {
			return true
		}
	}
	return false
}

func orderedCategories(byCategory map[string]int64) []StorageCategory {
	out := make([]StorageCategory, 0, len(storageCategoryOrder))
	for _, category := range storageCategoryOrder {
		out = append(out, StorageCategory{Category: category, Bytes: byCategory[category]})
	}
	return out
}

// storageTiers sums currently-stored bytes per tier from the open billing
// intervals (those without an end_time). Prices come from the live rate card.
func (s *SurrealStore) storageTiers(ctx context.Context, user models.RecordID) ([]StorageTier, error) {
	results, err := surrealdb.Query[[]struct {
		Tier  string  `json:"tier"`
		Bytes float64 `json:"bytes"`
	}](
		ctx, s.DB,
		`SELECT tier, <float> math::sum(size_bytes) AS bytes
		 FROM billing_storage_period
		 WHERE billed_to = $user AND end_time = NONE
		 GROUP BY tier`,
		map[string]any{"user": user},
	)
	if err != nil {
		return nil, fmt.Errorf("storage tiers: %w", err)
	}

	bytesByTier := map[string]int64{}
	for _, qr := range *results {
		for _, row := range qr.Result {
			bytesByTier[row.Tier] = int64(row.Bytes)
		}
	}

	out := make([]StorageTier, 0, len(storageTierOrder))
	for _, tier := range storageTierOrder {
		out = append(out, StorageTier{
			Tier:                tier,
			Bytes:               bytesByTier[tier],
			UnitPricePerGBMonth: s.pricing.StoragePricePerGBMonth(tier),
			Currency:            s.pricing.Currency,
		})
	}
	return out, nil
}

type storageInterval struct {
	Start time.Time  `json:"start_time"`
	End   *time.Time `json:"end_time"`
	Bytes float64    `json:"bytes"`
}

// storageHistory reconstructs daily cumulative stored bytes over the last year.
// Each billing interval contributes its size from start_time until end_time (or
// now, while still open), so summing the open intervals at each day's midnight
// reproduces the storage curve without per-day snapshots.
func (s *SurrealStore) storageHistory(ctx context.Context, user models.RecordID, now time.Time) ([]StoragePoint, error) {
	results, err := surrealdb.Query[[]storageInterval](
		ctx, s.DB,
		`SELECT start_time, end_time, <float> size_bytes AS bytes
		 FROM billing_storage_period
		 WHERE billed_to = $user`,
		map[string]any{"user": user},
	)
	if err != nil {
		return nil, fmt.Errorf("storage history: %w", err)
	}

	var intervals []storageInterval
	for _, qr := range *results {
		intervals = append(intervals, qr.Result...)
	}

	return buildStorageHistory(intervals, now), nil
}

// buildStorageHistory walks the last 366 day boundaries and, for each, sums the
// size of every interval that was open at that instant.
func buildStorageHistory(intervals []storageInterval, now time.Time) []StoragePoint {
	const days = 365
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	out := make([]StoragePoint, 0, days+1)
	for offset := days; offset >= 0; offset-- {
		// Past days are sampled at midnight; the final point uses the current
		// instant so the trend ends at the live total (matching the headline).
		instant := today.AddDate(0, 0, -offset)
		if offset == 0 {
			instant = now
		}
		var total float64
		for _, interval := range intervals {
			if interval.Start.After(instant) {
				continue
			}
			if interval.End != nil && !interval.End.After(instant) {
				continue
			}
			total += interval.Bytes
		}
		out = append(out, StoragePoint{Date: instant.Format("2006-01-02"), Bytes: int64(total)})
	}
	return out
}
