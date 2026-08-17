package provisioner

import (
	"context"
	"fmt"
	"sync"
)

// FakeProvisioner is an in-memory InstanceProvisioner for tests. It records
// provisioned handles without touching a real substrate so store logic (routing,
// lazy provisioning, idempotency) can be exercised in unit tests.
type FakeProvisioner struct {
	mu         sync.Mutex
	byOrg      map[string]InstanceHandle
	Provisions int // number of Provision calls, for asserting idempotency
	stats      ResourceStats
}

func NewFake() *FakeProvisioner {
	return &FakeProvisioner{byOrg: map[string]InstanceHandle{}}
}

func (f *FakeProvisioner) Provision(_ context.Context, orgID string) (InstanceHandle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Provisions++
	if h, ok := f.byOrg[orgID]; ok {
		return h, nil
	}
	h := InstanceHandle{
		Endpoint: fmt.Sprintf("ws://127.0.0.1:9%03d", len(f.byOrg)),
		Handle:   "fake-" + orgID,
		RootUser: "root",
		RootPass: "root",
		Host:     "127.0.0.1",
	}
	f.byOrg[orgID] = h
	return h, nil
}

func (f *FakeProvisioner) Destroy(_ context.Context, handle string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for org, h := range f.byOrg {
		if h.Handle == handle {
			delete(f.byOrg, org)
		}
	}
	return nil
}

func (f *FakeProvisioner) SetStats(s ResourceStats) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stats = s
}

func (f *FakeProvisioner) Stats(_ context.Context, _ string) (ResourceStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stats, nil
}
