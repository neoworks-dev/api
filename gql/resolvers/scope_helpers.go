package gql

import (
	"context"
	"fmt"

	gql_model "github.com/neoworks/auth/gql/model"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

type dbScopeGrant struct {
	ID               *models.RecordID `json:"id,omitempty"`
	Client           *models.RecordID `json:"client"`
	Raw              string           `json:"raw"`
	Entity           string           `json:"entity"`
	Action           string           `json:"action"`
	Enabled          bool             `json:"enabled"`
	OrganizationSlug *string          `json:"organization_slug,omitempty"`
}

func firstScopeGrant(results *[]surrealdb.QueryResult[[]dbScopeGrant]) *dbScopeGrant {
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			g := qr.Result[0]
			return &g
		}
	}
	return nil
}

func scopeGrantToGQL(g *dbScopeGrant, orgSlug string) *gql_model.ScopeGrant {
	id := ""
	if g.ID != nil {
		id = fmt.Sprintf("%v", g.ID.ID)
	}
	clientID := ""
	if g.Client != nil {
		clientID = fmt.Sprintf("%v", g.Client.ID)
	}
	var slug *string
	if orgSlug != "" {
		slug = &orgSlug
	}
	return &gql_model.ScopeGrant{
		ID:               id,
		ClientID:         clientID,
		Raw:              g.Raw,
		OrganizationSlug: slug,
		Entity:           g.Entity,
		Action:           g.Action,
		Enabled:          g.Enabled,
	}
}

// organizationBySlug resolves the `organization` token of a scope to a record id.
func (r *mutationResolver) organizationBySlug(ctx context.Context, slug string) (*models.RecordID, error) {
	results, err := surrealdb.Query[[]*models.RecordID](ctx, r.store.DB,
		"SELECT VALUE id FROM organization WHERE slug = $slug AND deleted_at = NONE LIMIT 1",
		map[string]any{"slug": slug},
	)
	if err != nil {
		return nil, fmt.Errorf("resolve organization: %w", err)
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0], nil
		}
	}
	return nil, nil
}
