package database

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/provisioner"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// surrealTarget is a resolved SurrealDB instance plus the root credentials to
// reach it. Every client database lives on its organization's dedicated instance.
type surrealTarget struct {
	Endpoint string
	User     string
	Pass     string
}

// UseInstanceProvisioner installs the substrate that provisions dedicated
// per-organization instances for pro-plan orgs. Optional: without it, every org
// (including pro) stays on the shared tenant instance.
func (s *SurrealStore) UseInstanceProvisioner(p provisioner.InstanceProvisioner, enc *Encryptor) {
	s.prov = p
	s.instanceEnc = enc
}

// UseSharedTenant points free-plan client databases at a dedicated shared
// SurrealDB instance instead of the control-plane connection.
func (s *SurrealStore) UseSharedTenant(endpoint, user, pass string) {
	s.sharedTenant = surrealTarget{Endpoint: endpoint, User: user, Pass: pass}
}

// UseThrottler installs per-tenant query admission control for the shared instance.
func (s *SurrealStore) UseThrottler(t Throttler) { s.throttle = t }

// InstanceProvisioner returns the configured provisioner, or nil when per-org
// instances are disabled.
func (s *SurrealStore) InstanceProvisioner() provisioner.InstanceProvisioner { return s.prov }

func (s *SurrealStore) sealSecret(plain string) string {
	return sealWith(s.instanceEnc, plain)
}

func (s *SurrealStore) openSecret(stored string) string {
	return openWith(s.instanceEnc, stored)
}

// tenantRoute is a resolved decision about where a client's databases live: the
// instance to connect to, the org's plan, and whether that instance is the shared
// one (which is what the query path throttles and time-limits more tightly).
type tenantRoute struct {
	target surrealTarget
	plan   string // "free" | "pro"
	shared bool
}

// routeForNamespace resolves the tenant route for a client namespace
// (client_{clientID}).
func (s *SurrealStore) routeForNamespace(ctx context.Context, namespace string) (tenantRoute, error) {
	return s.routeForClient(ctx, strings.TrimPrefix(namespace, "client_"))
}

// routeForClient decides which instance hosts a client's databases. Free-plan
// orgs (and pro orgs without a dedicated instance yet) route to the shared
// instance; pro orgs with an active org_instance route to it.
func (s *SurrealStore) routeForClient(ctx context.Context, clientID string) (tenantRoute, error) {
	if r, ok := s.targets.get(clientID); ok {
		return r, nil
	}
	orgRef, plan, err := s.clientOrgPlan(ctx, clientID)
	if err != nil {
		return tenantRoute{}, fmt.Errorf("resolve client org: %w", err)
	}
	if orgRef == nil {
		return tenantRoute{}, fmt.Errorf("client %q has no organization", clientID)
	}

	if plan == "pro" {
		if inst, err := s.activeOrgInstance(ctx, orgRef); err != nil {
			return tenantRoute{}, fmt.Errorf("resolve org instance: %w", err)
		} else if inst != nil {
			r := tenantRoute{target: instanceTarget(s, inst), plan: plan, shared: false}
			s.targets.put(clientID, r)
			return r, nil
		}
	}

	// Free orgs, and pro orgs not yet provisioned, live on the shared instance.
	r := tenantRoute{target: s.sharedTenant, plan: plan, shared: true}
	s.targets.put(clientID, r)
	return r, nil
}

// targetForNamespace resolves just the connection target for a client namespace.
func (s *SurrealStore) targetForNamespace(ctx context.Context, namespace string) (surrealTarget, error) {
	r, err := s.routeForNamespace(ctx, namespace)
	return r.target, err
}

func (s *SurrealStore) targetForClient(ctx context.Context, clientID string) (surrealTarget, error) {
	r, err := s.routeForClient(ctx, clientID)
	return r.target, err
}

// ensureTargetForClient resolves the client's instance, provisioning a dedicated
// one for pro-plan orgs when a provisioner is configured. Free orgs (and any org
// without a provisioner) resolve to the shared instance without provisioning.
// Called from the database-creation path.
func (s *SurrealStore) ensureTargetForClient(ctx context.Context, clientID string) (surrealTarget, error) {
	route, err := s.routeForClient(ctx, clientID)
	if err != nil {
		return surrealTarget{}, err
	}
	if !route.shared || route.plan != "pro" || s.prov == nil {
		return route.target, nil
	}
	return s.provisionDedicated(ctx, clientID)
}

// provisionDedicated lazily creates a pro org's dedicated instance on first use and
// caches the route. Guarded by a per-org lock and the org_instance UNIQUE index.
func (s *SurrealStore) provisionDedicated(ctx context.Context, clientID string) (surrealTarget, error) {
	orgRef, plan, err := s.clientOrgPlan(ctx, clientID)
	if err != nil {
		return surrealTarget{}, fmt.Errorf("resolve client org: %w", err)
	}
	if orgRef == nil {
		return surrealTarget{}, fmt.Errorf("client %q has no organization", clientID)
	}

	orgID := recordIDString(orgRef)
	lock := s.orgProvisionLock(orgID)
	lock.Lock()
	defer lock.Unlock()

	// Re-check under the lock: another request may have provisioned already.
	inst, err := s.activeOrgInstance(ctx, orgRef)
	if err != nil {
		return surrealTarget{}, fmt.Errorf("lookup org instance: %w", err)
	}
	if inst != nil {
		return s.cacheDedicated(clientID, plan, instanceTarget(s, inst)), nil
	}

	handle, err := s.prov.Provision(ctx, orgID)
	if err != nil {
		return surrealTarget{}, fmt.Errorf("provision instance: %w", err)
	}

	if err := s.recordOrgInstance(ctx, orgRef, handle); err != nil {
		// A concurrent process may have won the UNIQUE-org race; re-read and adopt
		// its instance, tearing down the one we just built to avoid an orphan.
		if adopted, lookupErr := s.activeOrgInstance(ctx, orgRef); lookupErr == nil && adopted != nil {
			_ = s.prov.Destroy(ctx, handle.Handle)
			return s.cacheDedicated(clientID, plan, instanceTarget(s, adopted)), nil
		}
		return surrealTarget{}, fmt.Errorf("record org instance: %w", err)
	}

	target := surrealTarget{Endpoint: handle.Endpoint, User: handle.RootUser, Pass: handle.RootPass}
	return s.cacheDedicated(clientID, plan, target), nil
}

func (s *SurrealStore) cacheDedicated(clientID, plan string, target surrealTarget) surrealTarget {
	s.targets.put(clientID, tenantRoute{target: target, plan: plan, shared: false})
	return target
}

// instanceTarget builds the connection target for a dedicated instance, opening
// the sealed root password in memory.
func instanceTarget(s *SurrealStore, inst *oauth.OrgInstance) surrealTarget {
	return surrealTarget{Endpoint: inst.Endpoint, User: inst.RootUser, Pass: s.openSecret(inst.RootPassRef)}
}

// clientOrgPlan returns the organization that owns a client and the org's plan
// (defaulting to free for rows predating the plan field), or a nil ref if the
// client has no organization.
func (s *SurrealStore) clientOrgPlan(ctx context.Context, clientID string) (*models.RecordID, string, error) {
	res, err := surrealdb.Query[[]struct {
		Organization *models.RecordID `json:"organization"`
		Plan         *string          `json:"plan"`
	}](ctx, s.DB,
		"SELECT organization, organization.plan AS plan FROM client WHERE id = $client LIMIT 1",
		map[string]any{"client": models.NewRecordID("client", clientID)})
	if err != nil {
		return nil, "", err
	}
	for _, qr := range *res {
		if len(qr.Result) > 0 {
			plan := "free"
			if qr.Result[0].Plan != nil && *qr.Result[0].Plan != "" {
				plan = *qr.Result[0].Plan
			}
			return qr.Result[0].Organization, plan, nil
		}
	}
	return nil, "free", nil
}

func (s *SurrealStore) activeOrgInstance(ctx context.Context, orgRef *models.RecordID) (*oauth.OrgInstance, error) {
	res, err := surrealdb.Query[[]oauth.OrgInstance](ctx, s.DB,
		`SELECT * FROM org_instance WHERE organization = $org AND status = "active" LIMIT 1`,
		map[string]any{"org": orgRef})
	if err != nil {
		return nil, err
	}
	for _, qr := range *res {
		if len(qr.Result) > 0 {
			return &qr.Result[0], nil
		}
	}
	return nil, nil
}

func (s *SurrealStore) recordOrgInstance(ctx context.Context, orgRef *models.RecordID, h provisioner.InstanceHandle) error {
	var host *string
	if h.Host != "" {
		host = &h.Host
	}
	_, err := surrealdb.Query[[]any](ctx, s.DB, `
		CREATE org_instance SET
			organization  = $organization,
			endpoint      = $endpoint,
			status        = "active",
			handle        = $handle,
			root_user     = $root_user,
			root_pass_ref = $root_pass_ref,
			host          = $host
	`, map[string]any{
		"organization":  orgRef,
		"endpoint":      h.Endpoint,
		"handle":        h.Handle,
		"root_user":     h.RootUser,
		"root_pass_ref": s.sealSecret(h.RootPass),
		"host":          host,
	})
	return err
}

func (s *SurrealStore) orgProvisionLock(orgID string) *sync.Mutex {
	actual, _ := s.provLocks.LoadOrStore(orgID, &sync.Mutex{})
	return actual.(*sync.Mutex)
}

// ── target cache ────────────────────────────────────────────────────────────

// targetCache memoizes clientID → tenantRoute for a short TTL so the data-plane
// query path does not hit the control plane on every request. Provisioning writes
// through it; a suspended/destroyed instance or a plan change clears within the TTL.
type targetCache struct {
	mu  sync.RWMutex
	ttl time.Duration
	m   map[string]targetEntry
}

type targetEntry struct {
	route   tenantRoute
	expires time.Time
}

func newTargetCache(ttl time.Duration) *targetCache {
	return &targetCache{ttl: ttl, m: map[string]targetEntry{}}
}

func (c *targetCache) get(clientID string) (tenantRoute, bool) {
	c.mu.RLock()
	entry, ok := c.m[clientID]
	c.mu.RUnlock()
	if !ok || time.Now().After(entry.expires) {
		return tenantRoute{}, false
	}
	return entry.route, true
}

func (c *targetCache) put(clientID string, r tenantRoute) {
	c.mu.Lock()
	c.m[clientID] = targetEntry{route: r, expires: time.Now().Add(c.ttl)}
	c.mu.Unlock()
}

func (c *targetCache) invalidate(clientID string) {
	c.mu.Lock()
	delete(c.m, clientID)
	c.mu.Unlock()
}
