package database

import (
	"context"
	"fmt"
	"log/slog"
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

// UseInstanceProvisioner installs the substrate that provisions per-organization
// instances. It is required: client-database operations fail without it.
func (s *SurrealStore) UseInstanceProvisioner(p provisioner.InstanceProvisioner, enc *Encryptor) {
	s.prov = p
	s.instanceEnc = enc
}

// InstanceProvisioner returns the configured provisioner, or nil when per-org
// instances are disabled.
func (s *SurrealStore) InstanceProvisioner() provisioner.InstanceProvisioner { return s.prov }

func (s *SurrealStore) sealSecret(plain string) string {
	if s.instanceEnc == nil {
		return plain
	}
	sealed, err := s.instanceEnc.Seal(plain)
	if err != nil {
		slog.Error("seal instance secret", "error", err)
		return plain
	}
	return sealed
}

func (s *SurrealStore) openSecret(stored string) string {
	if s.instanceEnc == nil {
		return stored
	}
	plain, err := s.instanceEnc.Open(stored)
	if err != nil {
		// Tolerate rows written before a key was configured (stored verbatim).
		return stored
	}
	return plain
}

// targetForNamespace resolves the instance hosting a client namespace
// (client_{clientID}). It errors when the client has no provisioned instance
// rather than silently reading elsewhere.
func (s *SurrealStore) targetForNamespace(ctx context.Context, namespace string) (surrealTarget, error) {
	clientID := strings.TrimPrefix(namespace, "client_")
	return s.targetForClient(ctx, clientID)
}

func (s *SurrealStore) targetForClient(ctx context.Context, clientID string) (surrealTarget, error) {
	if t, ok := s.targets.get(clientID); ok {
		return t, nil
	}
	orgRef, err := s.clientOrgRef(ctx, clientID)
	if err != nil {
		return surrealTarget{}, fmt.Errorf("resolve client org: %w", err)
	}
	if orgRef == nil {
		return surrealTarget{}, fmt.Errorf("client %q has no organization", clientID)
	}
	inst, err := s.activeOrgInstance(ctx, orgRef)
	if err != nil {
		return surrealTarget{}, fmt.Errorf("resolve org instance: %w", err)
	}
	if inst == nil {
		return surrealTarget{}, fmt.Errorf("no active instance for organization %q", recordIDString(orgRef))
	}
	t := surrealTarget{Endpoint: inst.Endpoint, User: inst.RootUser, Pass: s.openSecret(inst.RootPassRef)}
	s.targets.put(clientID, t)
	return t, nil
}

// ensureTargetForClient resolves the client's instance, provisioning the org's
// dedicated instance on first use. Called from the database-creation path.
func (s *SurrealStore) ensureTargetForClient(ctx context.Context, clientID string) (surrealTarget, error) {
	if t, ok := s.targets.get(clientID); ok {
		return t, nil
	}
	orgRef, err := s.clientOrgRef(ctx, clientID)
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
		t := surrealTarget{Endpoint: inst.Endpoint, User: inst.RootUser, Pass: s.openSecret(inst.RootPassRef)}
		s.targets.put(clientID, t)
		return t, nil
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
			t := surrealTarget{Endpoint: adopted.Endpoint, User: adopted.RootUser, Pass: s.openSecret(adopted.RootPassRef)}
			s.targets.put(clientID, t)
			return t, nil
		}
		return surrealTarget{}, fmt.Errorf("record org instance: %w", err)
	}

	t := surrealTarget{Endpoint: handle.Endpoint, User: handle.RootUser, Pass: handle.RootPass}
	s.targets.put(clientID, t)
	return t, nil
}

// clientOrgRef returns the organization that owns a client, or nil if the client
// has no organization.
func (s *SurrealStore) clientOrgRef(ctx context.Context, clientID string) (*models.RecordID, error) {
	res, err := surrealdb.Query[[]struct {
		Organization *models.RecordID `json:"organization"`
	}](ctx, s.DB,
		"SELECT organization FROM client WHERE id = $client LIMIT 1",
		map[string]any{"client": models.NewRecordID("client", clientID)})
	if err != nil {
		return nil, err
	}
	for _, qr := range *res {
		if len(qr.Result) > 0 {
			return qr.Result[0].Organization, nil
		}
	}
	return nil, nil
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

// targetCache memoizes clientID → surrealTarget for a short TTL so the data-plane
// query path does not hit the control plane on every request. Provisioning writes
// through it; a suspended/destroyed instance clears within the TTL.
type targetCache struct {
	mu  sync.RWMutex
	ttl time.Duration
	m   map[string]targetEntry
}

type targetEntry struct {
	target  surrealTarget
	expires time.Time
}

func newTargetCache(ttl time.Duration) *targetCache {
	return &targetCache{ttl: ttl, m: map[string]targetEntry{}}
}

func (c *targetCache) get(clientID string) (surrealTarget, bool) {
	c.mu.RLock()
	entry, ok := c.m[clientID]
	c.mu.RUnlock()
	if !ok || time.Now().After(entry.expires) {
		return surrealTarget{}, false
	}
	return entry.target, true
}

func (c *targetCache) put(clientID string, t surrealTarget) {
	c.mu.Lock()
	c.m[clientID] = targetEntry{target: t, expires: time.Now().Add(c.ttl)}
	c.mu.Unlock()
}

func (c *targetCache) invalidate(clientID string) {
	c.mu.Lock()
	delete(c.m, clientID)
	c.mu.Unlock()
}
