package dataplane

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/graphql-go/graphql"
	"github.com/neoworks/auth/storage/database"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// errDatabaseNotFound is returned when no active client_database matches the
// requested (client, name). The handler maps this to a 404.
var errDatabaseNotFound = errors.New("database not found")

// Engine builds and caches a runtime GraphQL schema per client database,
// generated from the validated client_table registry.
type Engine struct {
	store *database.SurrealStore
	mu    sync.RWMutex
	cache map[string]*compiled
}

type compiled struct {
	schema graphql.Schema
	// namespace is the per-client SurrealDB namespace (client_{clientID}); physicalDB
	// is the database within it.
	namespace  string
	physicalDB string
	// clientOrg is the bare id of the organization that owns this database's
	// client. It owns every org-scoped row written through this client.
	clientOrg string
}

func NewEngine(store *database.SurrealStore) *Engine {
	return &Engine{store: store, cache: map[string]*compiled{}}
}

func cacheKey(clientID, name string) string { return clientID + "/" + name }

// Invalidate drops the cached schema for a database so the next request rebuilds
// it. Called after the control plane creates or updates a database schema.
func (e *Engine) Invalidate(clientID, name string) {
	e.mu.Lock()
	delete(e.cache, cacheKey(clientID, name))
	e.mu.Unlock()
}

// schemaFor returns the cached compiled schema for (clientID, logical name),
// building it on first use. The physical SurrealDB database name is resolved
// from the control plane and returned for the resolvers' context.
func (e *Engine) schemaFor(ctx context.Context, clientID, name string) (*compiled, error) {
	key := cacheKey(clientID, name)

	e.mu.RLock()
	c, ok := e.cache[key]
	e.mu.RUnlock()
	if ok {
		return c, nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if c, ok := e.cache[key]; ok {
		return c, nil
	}

	c, err := e.build(ctx, clientID, name)
	if err != nil {
		return nil, err
	}
	e.cache[key] = c
	return c, nil
}

type cdbRow struct {
	ID        *models.RecordID `json:"id"`
	Namespace string           `json:"namespace"`
	DbName    string           `json:"db_name"`
}

type ctRow struct {
	Name            string         `json:"name"`
	Kind            string         `json:"kind"`
	Versioned       bool           `json:"versioned"`
	ValidatedSchema map[string]any `json:"validated_schema"`
}

func (e *Engine) build(ctx context.Context, clientID, name string) (*compiled, error) {
	clientRef := models.NewRecordID("client", clientID)

	dbres, err := surrealdb.Query[[]cdbRow](ctx, e.store.DB, `
		SELECT id, namespace, db_name FROM client_database
		WHERE client = $client AND name = $name AND status != "deleted"
		LIMIT 1
	`, map[string]any{"client": clientRef, "name": name})
	if err != nil {
		return nil, fmt.Errorf("lookup database: %w", err)
	}
	var cdb *cdbRow
	for _, qr := range *dbres {
		if len(qr.Result) > 0 {
			cdb = &qr.Result[0]
		}
		break
	}
	if cdb == nil || cdb.ID == nil {
		return nil, errDatabaseNotFound
	}

	// Resolve the organization that owns this client; it owns every org-scoped row.
	orgres, err := surrealdb.Query[[]struct {
		Organization *models.RecordID `json:"organization"`
	}](ctx, e.store.DB,
		"SELECT organization FROM client WHERE id = $client LIMIT 1",
		map[string]any{"client": clientRef})
	if err != nil {
		return nil, fmt.Errorf("lookup client org: %w", err)
	}
	var clientOrg string
	for _, qr := range *orgres {
		if len(qr.Result) > 0 && qr.Result[0].Organization != nil {
			clientOrg = fmt.Sprintf("%v", qr.Result[0].Organization.ID)
		}
		break
	}

	tres, err := surrealdb.Query[[]ctRow](ctx, e.store.DB, `
		SELECT name, kind, versioned, validated_schema FROM client_table
		WHERE database = $db AND kind IN ["data", "org"]
	`, map[string]any{"db": *cdb.ID})
	if err != nil {
		return nil, fmt.Errorf("lookup tables: %w", err)
	}

	var specs []tableSpec
	for _, qr := range *tres {
		for _, row := range qr.Result {
			spec, err := parseRegistrySchema(row.Kind, row.Versioned, row.ValidatedSchema)
			if err != nil {
				return nil, fmt.Errorf("parse table %q: %w", row.Name, err)
			}
			specs = append(specs, spec)
		}
		break
	}

	schema, err := buildSchema(e.store, specs)
	if err != nil {
		return nil, fmt.Errorf("build schema: %w", err)
	}
	return &compiled{schema: schema, namespace: cdb.Namespace, physicalDB: cdb.DbName, clientOrg: clientOrg}, nil
}
