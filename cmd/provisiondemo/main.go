// Command provisiondemo drives the real per-org provisioning code paths against a
// live kubernetes cluster so the orchestrator logic can be observed end to end. It
// runs inside the cluster (see deploy/k8s), reaching both the control-plane and the
// provisioned tenant instances over in-cluster Service DNS.
//
// Flow: seed a demo client under the seeded neoworks org → ProvisionClientDatabase
// (provisions the org's SurrealDB StatefulSet + runs the namespace/db/user DDL) →
// run queries to populate per-database query metrics → take one metering sample →
// read the usage report back. The StatefulSet is left running for inspection.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/neoworks/auth/provisioner"
	"github.com/neoworks/auth/storage/database"
	surrealdb "github.com/surrealdb/surrealdb.go"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	ctx := context.Background()

	store, err := database.NewSurrealStore(
		env("SURREAL_URL", "ws://control-surreal:8000/rpc"),
		env("SURREAL_USER", "root"),
		env("SURREAL_PASS", "root"),
		env("SURREAL_NS", "neoworks"),
		env("SURREAL_DB", "auth"),
	)
	if err != nil {
		log.Fatalf("connect control-plane store: %v", err)
	}

	prov := provisioner.NewKubernetesProvisioner(provisioner.KubernetesConfig{
		Image:     env("TENANT_SURREAL_IMAGE", "surrealdb/surrealdb:latest-dev"),
		Namespace: env("TENANT_K8S_NAMESPACE", "neoworks-tenants"),
	})
	store.UseInstanceProvisioner(prov, nil)

	const clientID = "democlient"
	const dbName = "appdb"

	// Seed a demo client under the org seeded by migration 002.
	if _, err := surrealdb.Query[[]any](ctx, store.DB,
		"UPSERT client:democlient SET organization = organization:neoworks, name = 'Demo Client'", nil); err != nil {
		log.Fatalf("seed client: %v", err)
	}

	log.Printf("→ provisioning database %q for client %q (this creates the org's k8s StatefulSet)", dbName, clientID)
	namespace, physicalDB, password, err := store.ProvisionClientDatabase(ctx, clientID, dbName)
	if err != nil {
		log.Fatalf("provision client database: %v", err)
	}
	log.Printf("✓ provisioned: namespace=%s db=%s rootPasswordBytes=%d", namespace, physicalDB, len(password))

	// Record the control-plane client_database row (normally done by the GraphQL
	// resolver) so usage lookups + metric attribution can resolve this database.
	if _, err := surrealdb.Query[[]any](ctx, store.DB,
		"DELETE client_database WHERE client = client:democlient AND name = $name", map[string]any{"name": dbName}); err != nil {
		log.Fatalf("clear prior client_database: %v", err)
	}
	if _, err := surrealdb.Query[[]any](ctx, store.DB,
		"CREATE client_database SET client = client:democlient, name = $name, namespace = $namespace, db_name = $db_name",
		map[string]any{"name": dbName, "namespace": namespace, "db_name": physicalDB}); err != nil {
		log.Fatalf("record client_database: %v", err)
	}

	// Exercise the brokered query path so per-database query metrics accrue.
	for i := 0; i < 5; i++ {
		if _, err := store.QueryClientDB(ctx, namespace, physicalDB,
			"CREATE demo SET n = $n, at = time::now()", map[string]any{"n": i}); err != nil {
			log.Printf("  query %d failed: %v", i, err)
		}
	}
	log.Printf("✓ ran 5 queries against the tenant database")

	// One metering cycle (short interval for the demo) persists instance_metric +
	// database_metric rows the usage report reads back.
	store.StartInstanceMetering(ctx, 2*time.Second)
	time.Sleep(5 * time.Second)

	report, err := store.DatabaseUsage(ctx, clientID, dbName, time.Now().Add(-time.Hour))
	if err != nil {
		log.Fatalf("read usage: %v", err)
	}
	pretty, _ := json.MarshalIndent(report, "", "  ")
	fmt.Printf("\n=== DatabaseUsage(%s/%s) ===\n%s\n", clientID, dbName, pretty)

	stats, err := prov.Stats(ctx, "neoworks-org-neoworks")
	if err != nil {
		log.Printf("stats: %v", err)
	}
	fmt.Printf("\n=== provisioner.Stats(neoworks-org-neoworks) ===\n%+v\n", stats)

	log.Printf("demo complete — tenant StatefulSet left running; inspect with: kubectl -n %s get statefulset,pod,svc,pvc",
		env("TENANT_K8S_NAMESPACE", "neoworks-tenants"))
}
