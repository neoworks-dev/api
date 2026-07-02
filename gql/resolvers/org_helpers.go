package gql

import (
	"context"
	"fmt"
	"time"

	gql_model "github.com/neoworks/auth/gql/model"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// errUnauthenticated is safe to surface to clients; it leaks nothing internal.
var errUnauthenticated = Public("unauthenticated")

type dbOrganization struct {
	ID           *models.RecordID `json:"id,omitempty"`
	Name         string           `json:"name"`
	Slug         string           `json:"slug"`
	Description  *string          `json:"description,omitempty"`
	LogoURL      *string          `json:"logo_url,omitempty"`
	BillingEmail *string          `json:"billing_email,omitempty"`
	CreatedAt    time.Time        `json:"created_at"`
}

type dbMembership struct {
	User *models.RecordID `json:"user"`
	Role string           `json:"role"`
}

func firstOrganization(results *[]surrealdb.QueryResult[[]dbOrganization]) *dbOrganization {
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			org := qr.Result[0]
			return &org
		}
	}
	return nil
}

func organizationToGQL(o *dbOrganization) *gql_model.Organization {
	id := ""
	if o.ID != nil {
		id = fmt.Sprintf("%v", o.ID.ID)
	}
	return &gql_model.Organization{
		ID:           id,
		Name:         o.Name,
		Slug:         o.Slug,
		Description:  o.Description,
		LogoURL:      o.LogoURL,
		BillingEmail: o.BillingEmail,
		CreatedAt:    o.CreatedAt.String(),
	}
}

func organizationsToGQL(results *[]surrealdb.QueryResult[[]dbOrganization]) []*gql_model.Organization {
	var out []*gql_model.Organization
	for _, qr := range *results {
		for i := range qr.Result {
			out = append(out, organizationToGQL(&qr.Result[i]))
		}
	}
	return out
}

// membershipRole returns the caller's role in an organization, or "" if not a member.
func (r *mutationResolver) membershipRole(ctx context.Context, userID string, orgRef models.RecordID) string {
	return membershipRole(ctx, r.store.DB, userID, orgRef)
}

func (r *queryResolver) membershipRole(ctx context.Context, userID string, orgRef models.RecordID) string {
	return membershipRole(ctx, r.store.DB, userID, orgRef)
}

func membershipRole(ctx context.Context, db *surrealdb.DB, userID string, orgRef models.RecordID) string {
	results, err := surrealdb.Query[[]struct {
		Role string `json:"role"`
	}](ctx, db,
		"SELECT role FROM membership WHERE in = $user AND out = $org LIMIT 1",
		map[string]any{"user": models.NewRecordID("user", userID), "org": orgRef},
	)
	if err != nil {
		return ""
	}
	for _, qr := range *results {
		if len(qr.Result) > 0 {
			return qr.Result[0].Role
		}
	}
	return ""
}

func (r *mutationResolver) callerIsMember(ctx context.Context, userID string, orgRef models.RecordID) bool {
	return r.membershipRole(ctx, userID, orgRef) != ""
}

func (r *queryResolver) callerIsMember(ctx context.Context, userID string, orgRef models.RecordID) bool {
	return r.membershipRole(ctx, userID, orgRef) != ""
}

func (r *mutationResolver) callerCanAdminOrg(ctx context.Context, userID string, orgRef models.RecordID) bool {
	role := r.membershipRole(ctx, userID, orgRef)
	return role == "owner" || role == "admin"
}

func (r *queryResolver) callerCanAdminOrg(ctx context.Context, userID string, orgRef models.RecordID) bool {
	role := r.membershipRole(ctx, userID, orgRef)
	return role == "owner" || role == "admin"
}
