package database

import (
	"context"
	"errors"

	"github.com/neoworks/auth/ownership"
)

// MissingPermissionError means the user holds no grant covering Permission for
// the owner they act for.
type MissingPermissionError struct {
	Permission ownership.Permission
}

func (err *MissingPermissionError) Error() string {
	return "missing permission " + string(err.Permission)
}

// requirePermission returns the grants the user holds for the owner of handle,
// or a MissingPermissionError when none covers permission. ErrNotFound means no
// owner holds the handle.
func (s *SurrealStore) requirePermission(ctx context.Context, userID string, handle string, permission ownership.Permission) error {
	grants, err := s.GrantsFor(ctx, userID, handle)
	if errors.Is(err, ErrForbidden) {
		return &MissingPermissionError{Permission: permission}
	}
	if err != nil {
		return err
	}
	if !ownership.Allows(grants, permission, "") {
		return &MissingPermissionError{Permission: permission}
	}
	return nil
}

// requireSchemaPublisher requires schemas.publish for the owner of the scope.
func (s *SurrealStore) requireSchemaPublisher(ctx context.Context, userID string, scope string) error {
	return s.requirePermission(ctx, userID, scope, ownership.SchemasPublish)
}

// authorizeSchemaPublisher additionally refuses scopes of archived organizations.
func (s *SurrealStore) authorizeSchemaPublisher(ctx context.Context, userID string, scope string) error {
	if err := s.requireSchemaPublisher(ctx, userID, scope); err != nil {
		return err
	}
	archived, err := s.IsOwnerArchived(ctx, scope)
	if err != nil {
		return err
	}
	if archived {
		return ErrArchived
	}
	return nil
}
