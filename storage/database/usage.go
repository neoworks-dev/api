package database

import (
	"context"
	"fmt"
	"time"

	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// UsageSample is one instance-level time-series point (CPU/memory/storage).
type UsageSample struct {
	SampledAt    time.Time
	CPUPercent   float64
	MemBytes     int64
	MemPercent   float64
	StorageBytes int64
}

// QueryUsageSample is one per-database query time-series point.
type QueryUsageSample struct {
	SampledAt         time.Time
	QueryCount        int64
	AvgLatencyMs      float64
	ActiveConnections int
}

// DatabaseUsageCurrent is the latest snapshot shown as gauges. Instance figures
// come from the most recent persisted sample; query figures are read live from
// the in-memory counters.
type DatabaseUsageCurrent struct {
	CPUPercent        float64
	MemBytes          int64
	MemPercent        float64
	StorageBytes      int64
	AvgLatencyMs      float64
	ActiveConnections int
	QueryCount        int64
}

// DatabaseUsageReport bundles the current snapshot with the two time series.
type DatabaseUsageReport struct {
	Current        DatabaseUsageCurrent
	InstanceSeries []UsageSample
	QuerySeries    []QueryUsageSample
}

// metric row scan shapes.
type instanceMetricRow struct {
	SampledAt    time.Time `json:"sampled_at"`
	CPUPercent   float64   `json:"cpu_percent"`
	MemBytes     int64     `json:"mem_bytes"`
	MemPercent   float64   `json:"mem_percent"`
	StorageBytes int64     `json:"storage_bytes"`
}

type databaseMetricRow struct {
	SampledAt         time.Time `json:"sampled_at"`
	QueryCount        int64     `json:"query_count"`
	AvgLatencyMs      float64   `json:"avg_latency_ms"`
	ActiveConnections int       `json:"active_connections"`
}

// DatabaseUsage assembles the usage report for one client database: the latest
// instance snapshot, the live query counters, and both persisted time series
// back to `since`. CPU/memory/storage reflect the shared org instance hosting
// the database; query stats are specific to this database.
func (s *SurrealStore) DatabaseUsage(ctx context.Context, clientID, name string, since time.Time) (*DatabaseUsageReport, error) {
	dbRef, namespace, dbName, orgRef, err := s.lookupUsageDatabase(ctx, clientID, name)
	if err != nil {
		return nil, err
	}

	var instanceID *models.RecordID
	if orgRef != nil {
		if inst, lookupErr := s.activeOrgInstance(ctx, orgRef); lookupErr == nil && inst != nil {
			instanceID = inst.ID
		}
	}

	report := &DatabaseUsageReport{}

	if instanceID != nil {
		latest, err := s.latestInstanceMetric(ctx, instanceID)
		if err != nil {
			return nil, err
		}
		if latest != nil {
			report.Current.CPUPercent = latest.CPUPercent
			report.Current.MemBytes = latest.MemBytes
			report.Current.MemPercent = latest.MemPercent
			report.Current.StorageBytes = latest.StorageBytes
		}
		report.InstanceSeries, err = s.instanceMetricSeries(ctx, instanceID, since)
		if err != nil {
			return nil, err
		}
	}

	live := s.queryMetrics.current(namespace, dbName)
	report.Current.QueryCount = live.QueryCount
	report.Current.AvgLatencyMs = live.AvgLatencyMs
	report.Current.ActiveConnections = live.ActiveConnections

	report.QuerySeries, err = s.databaseMetricSeries(ctx, dbRef, since)
	if err != nil {
		return nil, err
	}

	return report, nil
}

func (s *SurrealStore) lookupUsageDatabase(ctx context.Context, clientID, name string) (dbRef *models.RecordID, namespace, dbName string, orgRef *models.RecordID, err error) {
	res, err := surrealdb.Query[[]struct {
		ID           *models.RecordID `json:"id"`
		Namespace    string           `json:"namespace"`
		DbName       string           `json:"db_name"`
		Organization *models.RecordID `json:"organization"`
	}](ctx, s.DB, `
		SELECT id, namespace, db_name, client.organization AS organization FROM client_database
		WHERE client = $client AND name = $name AND status != "deleted"
		LIMIT 1
	`, map[string]any{"client": models.NewRecordID("client", clientID), "name": name})
	if err != nil {
		return nil, "", "", nil, fmt.Errorf("lookup database: %w", err)
	}
	for _, qr := range *res {
		if len(qr.Result) > 0 {
			row := qr.Result[0]
			return row.ID, row.Namespace, row.DbName, row.Organization, nil
		}
	}
	return nil, "", "", nil, ErrNotFound
}

func (s *SurrealStore) latestInstanceMetric(ctx context.Context, instanceID *models.RecordID) (*UsageSample, error) {
	res, err := surrealdb.Query[[]instanceMetricRow](ctx, s.DB, `
		SELECT * FROM instance_metric WHERE instance = $instance ORDER BY sampled_at DESC LIMIT 1
	`, map[string]any{"instance": instanceID})
	if err != nil {
		return nil, fmt.Errorf("latest instance metric: %w", err)
	}
	for _, qr := range *res {
		if len(qr.Result) > 0 {
			return instanceRowToSample(qr.Result[0]), nil
		}
	}
	return nil, nil
}

func (s *SurrealStore) instanceMetricSeries(ctx context.Context, instanceID *models.RecordID, since time.Time) ([]UsageSample, error) {
	res, err := surrealdb.Query[[]instanceMetricRow](ctx, s.DB, `
		SELECT * FROM instance_metric
		WHERE instance = $instance AND sampled_at >= $since
		ORDER BY sampled_at ASC
	`, map[string]any{"instance": instanceID, "since": since})
	if err != nil {
		return nil, fmt.Errorf("instance metric series: %w", err)
	}
	for _, qr := range *res {
		out := make([]UsageSample, len(qr.Result))
		for i := range qr.Result {
			out[i] = *instanceRowToSample(qr.Result[i])
		}
		return out, nil
	}
	return nil, nil
}

func (s *SurrealStore) databaseMetricSeries(ctx context.Context, dbRef *models.RecordID, since time.Time) ([]QueryUsageSample, error) {
	res, err := surrealdb.Query[[]databaseMetricRow](ctx, s.DB, `
		SELECT * FROM database_metric
		WHERE database = $database AND sampled_at >= $since
		ORDER BY sampled_at ASC
	`, map[string]any{"database": dbRef, "since": since})
	if err != nil {
		return nil, fmt.Errorf("database metric series: %w", err)
	}
	for _, qr := range *res {
		out := make([]QueryUsageSample, len(qr.Result))
		for i := range qr.Result {
			row := qr.Result[i]
			out[i] = QueryUsageSample{
				SampledAt:         row.SampledAt,
				QueryCount:        row.QueryCount,
				AvgLatencyMs:      row.AvgLatencyMs,
				ActiveConnections: row.ActiveConnections,
			}
		}
		return out, nil
	}
	return nil, nil
}

func instanceRowToSample(row instanceMetricRow) *UsageSample {
	return &UsageSample{
		SampledAt:    row.SampledAt,
		CPUPercent:   row.CPUPercent,
		MemBytes:     row.MemBytes,
		MemPercent:   row.MemPercent,
		StorageBytes: row.StorageBytes,
	}
}
