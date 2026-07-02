package database

import (
	"context"
	"log/slog"
	"time"

	"github.com/neoworks/auth/oauth"
	surrealdb "github.com/surrealdb/surrealdb.go"
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
