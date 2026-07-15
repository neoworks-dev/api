package gql

import (
	"time"

	gql_model "github.com/neoworks/auth/gql/model"
	"github.com/neoworks/auth/storage/database"
)

const defaultUsageWindowMinutes = 60

func usageReportToGQL(report *database.DatabaseUsageReport) *gql_model.DatabaseUsage {
	out := &gql_model.DatabaseUsage{
		Current: &gql_model.DatabaseUsageCurrent{
			CPUPercent:        report.Current.CPUPercent,
			MemBytes:          float64(report.Current.MemBytes),
			MemPercent:        report.Current.MemPercent,
			StorageBytes:      float64(report.Current.StorageBytes),
			AvgLatencyMs:      report.Current.AvgLatencyMs,
			ActiveConnections: report.Current.ActiveConnections,
			QueryCount:        int(report.Current.QueryCount),
		},
		InstanceSeries: make([]*gql_model.UsagePoint, len(report.InstanceSeries)),
		QuerySeries:    make([]*gql_model.QueryUsagePoint, len(report.QuerySeries)),
	}
	for i, sample := range report.InstanceSeries {
		out.InstanceSeries[i] = &gql_model.UsagePoint{
			SampledAt:    sample.SampledAt.Format(time.RFC3339),
			CPUPercent:   sample.CPUPercent,
			MemBytes:     float64(sample.MemBytes),
			MemPercent:   sample.MemPercent,
			StorageBytes: float64(sample.StorageBytes),
		}
	}
	for i, sample := range report.QuerySeries {
		out.QuerySeries[i] = &gql_model.QueryUsagePoint{
			SampledAt:         sample.SampledAt.Format(time.RFC3339),
			QueryCount:        int(sample.QueryCount),
			AvgLatencyMs:      sample.AvgLatencyMs,
			ActiveConnections: sample.ActiveConnections,
		}
	}
	return out
}
