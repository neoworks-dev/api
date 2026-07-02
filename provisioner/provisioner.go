// Package provisioner manages the lifecycle of a dedicated SurrealDB instance per
// organization. Isolating each org on its own instance turns the org into a hard
// compute + security boundary (namespaces alone share a runtime) and a clean unit
// to meter and bill.
//
// The InstanceProvisioner interface hides the substrate. The docker driver runs
// instances as containers on the host; a future kubernetes driver can implement
// the same interface without touching callers.
package provisioner

import "context"

// InstanceHandle identifies a provisioned SurrealDB instance and how to reach it
// as root. RootPass is plaintext in memory only; the caller seals it before
// persisting the handle.
type InstanceHandle struct {
	Endpoint string // ws:// admin endpoint the API dials
	Handle   string // opaque driver handle (docker container id/name)
	RootUser string
	RootPass string
	Host     string // best-effort host the instance runs on, for diagnostics
}

// ResourceStats is a point-in-time sample used to accrue usage-based billing.
type ResourceStats struct {
	CPUPercent   float64 // instantaneous CPU load; the sampler integrates it over the window
	StorageBytes int64   // on-disk size of the instance's data volume
}

// InstanceProvisioner is the substrate-agnostic contract for per-org instances.
// Provision must be idempotent for a given orgID.
type InstanceProvisioner interface {
	Provision(ctx context.Context, orgID string) (InstanceHandle, error)
	Destroy(ctx context.Context, handle string) error
	Stats(ctx context.Context, handle string) (ResourceStats, error)
}
