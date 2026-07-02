package gql

import (
	"context"
	"fmt"

	gql_model "github.com/neoworks/auth/gql/model"
	"github.com/neoworks/auth/middleware"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

type dbScopeDatabase struct {
	ID   *models.RecordID `json:"id,omitempty"`
	Name string           `json:"name"`
}

type dbScopeTable struct {
	Name     string           `json:"name"`
	Kind     string           `json:"kind"`
	Database *models.RecordID `json:"database"`
}

// loadOrganizationScopeEntities aggregates the data entities across every client
// database owned by an organization's clients, for building scope selections.
func (r *queryResolver) loadOrganizationScopeEntities(ctx context.Context, organizationID string) ([]*gql_model.ScopeEntity, error) {
	claim := middleware.ClaimFromContext(ctx)
	if claim == nil {
		return nil, errUnauthenticated
	}
	orgRef := models.NewRecordID("organization", organizationID)
	if !r.callerIsMember(ctx, claim.Subject, orgRef) {
		return nil, Public("forbidden: caller is not a member of this organization")
	}

	// Databases owned by the org's clients (client_database.client.organization).
	dbResults, err := surrealdb.Query[[]dbScopeDatabase](ctx, r.store.DB,
		`SELECT id, name FROM client_database
		 WHERE client.organization = $org AND status != "deleted"`,
		map[string]any{"org": orgRef},
	)
	if err != nil {
		return nil, fmt.Errorf("list org databases: %w", err)
	}

	dbNameByID := map[string]string{}
	var dbIDs []models.RecordID
	for _, qr := range *dbResults {
		for i := range qr.Result {
			database := qr.Result[i]
			if database.ID == nil {
				continue
			}
			dbNameByID[fmt.Sprintf("%v", *database.ID)] = database.Name
			dbIDs = append(dbIDs, *database.ID)
		}
	}
	if len(dbIDs) == 0 {
		return []*gql_model.ScopeEntity{}, nil
	}

	tableResults, err := surrealdb.Query[[]dbScopeTable](ctx, r.store.DB,
		`SELECT name, kind, database FROM client_table WHERE database IN $dbs`,
		map[string]any{"dbs": dbIDs},
	)
	if err != nil {
		return nil, fmt.Errorf("list org entities: %w", err)
	}

	out := []*gql_model.ScopeEntity{}
	for _, qr := range *tableResults {
		for i := range qr.Result {
			table := qr.Result[i]
			databaseName := ""
			if table.Database != nil {
				databaseName = dbNameByID[fmt.Sprintf("%v", *table.Database)]
			}
			out = append(out, &gql_model.ScopeEntity{
				Database: databaseName,
				Entity:   table.Name,
				Kind:     table.Kind,
			})
		}
	}
	return out, nil
}
