package gql

import (
	"context"

	"github.com/neoworks/auth/middleware"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// callerUser returns the authenticated caller's user record, or ok=false when
// the request is unauthenticated.
func callerUser(ctx context.Context) (models.RecordID, bool) {
	claim := middleware.ClaimFromContext(ctx)
	if claim == nil {
		return models.RecordID{}, false
	}
	return models.NewRecordID("user", claim.Subject), true
}
