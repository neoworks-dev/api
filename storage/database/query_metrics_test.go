package database

import "testing"

func TestQueryMetricsTrackAndCurrent(t *testing.T) {
	m := newQueryMetrics()

	done := m.track("client_abc", "app")
	// While in-flight: counted as an active connection, not yet a completed query.
	if got := m.current("client_abc", "app"); got.ActiveConnections != 1 || got.QueryCount != 0 {
		t.Fatalf("mid-flight current = %+v, want ActiveConnections=1 QueryCount=0", got)
	}
	done()

	got := m.current("client_abc", "app")
	if got.ActiveConnections != 0 {
		t.Errorf("ActiveConnections = %d, want 0", got.ActiveConnections)
	}
	if got.QueryCount != 1 {
		t.Errorf("QueryCount = %d, want 1", got.QueryCount)
	}
	if got.AvgLatencyMs < 0 {
		t.Errorf("AvgLatencyMs = %v, want >= 0", got.AvgLatencyMs)
	}
}

func TestQueryMetricsDrainResetsWindow(t *testing.T) {
	m := newQueryMetrics()
	m.track("client_abc", "app")() // one completed query
	m.track("client_abc", "app")()

	samples := m.drain()
	if len(samples) != 1 {
		t.Fatalf("drain returned %d samples, want 1", len(samples))
	}
	if samples[0].QueryCount != 2 {
		t.Errorf("QueryCount = %d, want 2", samples[0].QueryCount)
	}
	if samples[0].Namespace != "client_abc" || samples[0].DbName != "app" {
		t.Errorf("sample identity = %q/%q, want client_abc/app", samples[0].Namespace, samples[0].DbName)
	}

	// After draining, the window is reset and the idle database is dropped.
	if got := m.current("client_abc", "app"); got.QueryCount != 0 {
		t.Errorf("post-drain QueryCount = %d, want 0", got.QueryCount)
	}
	if next := m.drain(); len(next) != 0 {
		t.Errorf("second drain returned %d samples, want 0", len(next))
	}
}

func TestQueryMetricsNilSafe(t *testing.T) {
	var m *queryMetrics
	// All methods must tolerate a nil receiver so callers need no guard.
	m.track("ns", "db")()
	if got := m.current("ns", "db"); got != (queryUsage{}) {
		t.Errorf("nil current = %+v, want zero", got)
	}
	if got := m.drain(); got != nil {
		t.Errorf("nil drain = %+v, want nil", got)
	}
}
