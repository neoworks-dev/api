package database

import (
	"sync"
	"time"
)

// queryMetrics accumulates per-database query latency and in-flight counts for
// the usage dashboard. SurrealDB exposes neither, so the API measures them as it
// brokers every client-database query. Counters accrue between metering samples;
// drain folds them into the persisted time-series and resets the window.
type queryMetrics struct {
	mu    sync.Mutex
	stats map[string]*dbQueryStat
}

type dbQueryStat struct {
	namespace    string
	dbName       string
	inFlight     int
	peakInFlight int
	count        int64
	totalLatency time.Duration
}

func newQueryMetrics() *queryMetrics {
	return &queryMetrics{stats: map[string]*dbQueryStat{}}
}

func queryMetricsKey(namespace, dbName string) string { return namespace + "/" + dbName }

// track marks a query in-flight against a database and returns a function to call
// when the query completes, which records its latency. Safe for concurrent use
// and nil-safe so callers need no guard.
func (m *queryMetrics) track(namespace, dbName string) func() {
	if m == nil {
		return func() {}
	}
	key := queryMetricsKey(namespace, dbName)
	start := time.Now()

	m.mu.Lock()
	stat := m.stats[key]
	if stat == nil {
		stat = &dbQueryStat{namespace: namespace, dbName: dbName}
		m.stats[key] = stat
	}
	stat.inFlight++
	if stat.inFlight > stat.peakInFlight {
		stat.peakInFlight = stat.inFlight
	}
	m.mu.Unlock()

	return func() {
		elapsed := time.Since(start)
		m.mu.Lock()
		stat.count++
		stat.totalLatency += elapsed
		stat.inFlight--
		m.mu.Unlock()
	}
}

// queryUsage is a point-in-time view of one database's query activity.
type queryUsage struct {
	QueryCount        int64
	AvgLatencyMs      float64
	ActiveConnections int
}

// current returns the accumulated window for a single database, used for the
// dashboard's live "current" figures.
func (m *queryMetrics) current(namespace, dbName string) queryUsage {
	if m == nil {
		return queryUsage{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	stat := m.stats[queryMetricsKey(namespace, dbName)]
	if stat == nil {
		return queryUsage{}
	}
	return queryUsage{
		QueryCount:        stat.count,
		AvgLatencyMs:      avgLatencyMs(stat.totalLatency, stat.count),
		ActiveConnections: stat.inFlight,
	}
}

// querySample is one database's activity over the just-elapsed sample window.
type querySample struct {
	Namespace         string
	DbName            string
	QueryCount        int64
	AvgLatencyMs      float64
	ActiveConnections int
}

// drain returns a sample per database that saw activity since the last call and
// resets the window counters. In-flight counts are live (not windowed) so they
// carry over; peakInFlight is reported as the window's active-connection high and
// then reseeded to the current in-flight count. Idle databases are dropped to
// keep the map bounded.
func (m *queryMetrics) drain() []querySample {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []querySample
	for key, stat := range m.stats {
		if stat.count == 0 && stat.inFlight == 0 {
			delete(m.stats, key)
			continue
		}
		out = append(out, querySample{
			Namespace:         stat.namespace,
			DbName:            stat.dbName,
			QueryCount:        stat.count,
			AvgLatencyMs:      avgLatencyMs(stat.totalLatency, stat.count),
			ActiveConnections: stat.peakInFlight,
		})
		stat.count = 0
		stat.totalLatency = 0
		stat.peakInFlight = stat.inFlight
	}
	return out
}

func avgLatencyMs(total time.Duration, count int64) float64 {
	if count == 0 {
		return 0
	}
	return float64(total.Nanoseconds()) / float64(count) / 1e6
}
