package database

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/provisioner"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// StartInstanceMetering samples every active org instance on an interval and
// records a compute billing event proportional to CPU load. It is a no-op when
// per-org instances are disabled. Storage metering (open GB-month periods) is
// tracked as a follow-up; this pass covers compute only.
func (s *SurrealStore) StartInstanceMetering(ctx context.Context, interval time.Duration) {
	if s.prov == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.sampleInstances(ctx, interval)
			}
		}
	}()
}

func (s *SurrealStore) sampleInstances(ctx context.Context, window time.Duration) {
	sampledAt := time.Now()

	instances, err := s.listActiveInstances(ctx)
	if err != nil {
		slog.Error("metering: list instances", "error", err)
		return
	}
	for _, inst := range instances {
		if inst.Organization == nil {
			continue
		}
		stats, err := s.prov.Stats(ctx, inst.Handle)
		if err != nil {
			slog.Error("metering: stats", "error", err, "handle", inst.Handle)
			continue
		}

		// Persist the raw sample for the usage dashboard's time-series charts.
		s.recordInstanceMetric(ctx, inst.ID, inst.Organization, stats, sampledAt)

		// Integrate instantaneous CPU load over the sample window into CPU-seconds.
		cpuSeconds := stats.CPUPercent / 100 * window.Seconds()
		if cpuSeconds <= 0 {
			continue
		}
		err = s.CreateComputeBillingEvent(ctx, BillingEventParams{
			BilledTo: *inst.Organization,
			Units:    cpuSeconds,
			Currency: "USD",
			Ref:      inst.ID,
		})
		if err != nil {
			slog.Error("metering: record compute event", "error", err, "org", recordIDString(inst.Organization))
		}
	}

	// Fold the query counters accrued since the last tick into per-database rows.
	s.sampleQueryMetrics(ctx, sampledAt)
}

// recordInstanceMetric writes one instance-level usage sample (CPU/memory/storage).
func (s *SurrealStore) recordInstanceMetric(ctx context.Context, instanceID, orgRef *models.RecordID, stats provisioner.ResourceStats, sampledAt time.Time) {
	if instanceID == nil {
		return
	}
	_, err := surrealdb.Query[[]any](ctx, s.DB, `
		CREATE instance_metric SET
			instance      = $instance,
			organization  = $organization,
			cpu_percent   = $cpu_percent,
			mem_bytes     = $mem_bytes,
			mem_percent   = $mem_percent,
			storage_bytes = $storage_bytes,
			sampled_at    = $sampled_at
	`, map[string]any{
		"instance":      instanceID,
		"organization":  orgRef,
		"cpu_percent":   stats.CPUPercent,
		"mem_bytes":     stats.MemBytes,
		"mem_percent":   stats.MemPercent,
		"storage_bytes": stats.StorageBytes,
		"sampled_at":    sampledAt,
	})
	if err != nil {
		slog.Error("metering: record instance metric", "error", err, "instance", recordIDString(instanceID))
	}
}

// sampleQueryMetrics drains the in-memory query counters and writes a
// database_metric row per database that saw activity in the window.
func (s *SurrealStore) sampleQueryMetrics(ctx context.Context, sampledAt time.Time) {
	for _, sample := range s.queryMetrics.drain() {
		s.recordDatabaseMetric(ctx, sample, sampledAt)
	}
}

func (s *SurrealStore) recordDatabaseMetric(ctx context.Context, sample querySample, sampledAt time.Time) {
	dbID, orgRef, err := s.resolveMetricDatabase(ctx, sample.Namespace, sample.DbName)
	if err != nil {
		slog.Error("metering: resolve database", "error", err, "namespace", sample.Namespace, "db", sample.DbName)
		return
	}
	if dbID == nil {
		return
	}

	assignments := []string{
		"database = $database",
		"query_count = $query_count",
		"avg_latency_ms = $avg_latency_ms",
		"active_connections = $active_connections",
		"sampled_at = $sampled_at",
	}
	params := map[string]any{
		"database":           dbID,
		"query_count":        sample.QueryCount,
		"avg_latency_ms":     sample.AvgLatencyMs,
		"active_connections": sample.ActiveConnections,
		"sampled_at":         sampledAt,
	}
	// instance is an option<record>; only set it when resolvable so it defaults to NONE.
	if orgRef != nil {
		if inst, lookupErr := s.activeOrgInstance(ctx, orgRef); lookupErr == nil && inst != nil {
			assignments = append(assignments, "instance = $instance")
			params["instance"] = inst.ID
		}
	}

	query := "CREATE database_metric SET " + strings.Join(assignments, ", ")
	if _, err := surrealdb.Query[[]any](ctx, s.DB, query, params); err != nil {
		slog.Error("metering: record database metric", "error", err, "db", recordIDString(dbID))
	}
}

// resolveMetricDatabase maps a (namespace, db_name) pair to the client_database
// record and its owning organization.
func (s *SurrealStore) resolveMetricDatabase(ctx context.Context, namespace, dbName string) (*models.RecordID, *models.RecordID, error) {
	res, err := surrealdb.Query[[]struct {
		ID           *models.RecordID `json:"id"`
		Organization *models.RecordID `json:"organization"`
	}](ctx, s.DB, `
		SELECT id, client.organization AS organization FROM client_database
		WHERE namespace = $namespace AND db_name = $db_name AND status != "deleted"
		LIMIT 1
	`, map[string]any{"namespace": namespace, "db_name": dbName})
	if err != nil {
		return nil, nil, err
	}
	for _, qr := range *res {
		if len(qr.Result) > 0 {
			return qr.Result[0].ID, qr.Result[0].Organization, nil
		}
	}
	return nil, nil, nil
}

func (s *SurrealStore) listActiveInstances(ctx context.Context) ([]oauth.OrgInstance, error) {
	res, err := surrealdb.Query[[]oauth.OrgInstance](ctx, s.DB,
		`SELECT * FROM org_instance WHERE status = "active"`, nil)
	if err != nil {
		return nil, err
	}
	for _, qr := range *res {
		return qr.Result, nil
	}
	return nil, nil
}
