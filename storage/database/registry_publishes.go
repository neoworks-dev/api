package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/neoworks/auth/registrycompat"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

const maxListedPublishes = 200

// RegistryActor is who made a publish attempt.
type RegistryActor struct {
	Handle      string `json:"handle"`
	Kind        string `json:"kind"`
	DisplayName string `json:"displayName"`
	Verified    bool   `json:"verified"`
}

// RegistryPublishAttempt is one publish into a schema's scope, accepted or refused.
type RegistryPublishAttempt struct {
	Version    string                     `json:"version"`
	At         time.Time                  `json:"at"`
	Actor      RegistryActor              `json:"actor"`
	Accepted   bool                       `json:"accepted"`
	Violations []registrycompat.Violation `json:"violations"`
}

type dbPublishAttempt struct {
	Version    string                     `json:"version"`
	Accepted   bool                       `json:"accepted"`
	Violations []registrycompat.Violation `json:"violations"`
	CreatedAt  time.Time                  `json:"created_at"`
	Handle     *string                    `json:"handle"`
	FirstName  *string                    `json:"first_name"`
	LastName   *string                    `json:"last_name"`
}

func (row dbPublishAttempt) toAttempt() RegistryPublishAttempt {
	violations := row.Violations
	if violations == nil {
		violations = []registrycompat.Violation{}
	}
	return RegistryPublishAttempt{
		Version: row.Version, At: row.CreatedAt, Accepted: row.Accepted, Violations: violations,
		Actor: RegistryActor{Handle: textOrEmpty(row.Handle), Kind: "user", DisplayName: row.displayName(), Verified: false},
	}
}

func (row dbPublishAttempt) displayName() string {
	name := strings.TrimSpace(textOrEmpty(row.FirstName) + " " + textOrEmpty(row.LastName))
	if name != "" {
		return name
	}
	return textOrEmpty(row.Handle)
}

func textOrEmpty(text *string) string {
	if text == nil {
		return ""
	}
	return *text
}

const registryPublishesStatement = `
	SELECT version, accepted, violations, created_at,
		actor.handle AS handle, actor.first_name AS first_name, actor.last_name AS last_name
	FROM registry_publish WHERE schema = $schema ORDER BY created_at DESC LIMIT $limit`

// ListRegistryPublishes returns the publish attempts of a schema, newest first.
// Only users who may publish into its scope read them, because refused attempts
// are not part of the public registry.
func (s *SurrealStore) ListRegistryPublishes(ctx context.Context, userID, scope, name string) ([]RegistryPublishAttempt, error) {
	schemaRow, err := s.getRegistrySchemaRow(ctx, scope, name)
	if err != nil {
		return nil, err
	}
	if err := s.requireSchemaPublisher(ctx, userID, scope); err != nil {
		return nil, err
	}
	rows, err := queryRows[dbPublishAttempt](ctx, s.DB, registryPublishesStatement,
		map[string]any{"schema": schemaRow.ID, "limit": maxListedPublishes})
	if err != nil {
		return nil, fmt.Errorf("list registry publishes: %w", err)
	}
	attempts := make([]RegistryPublishAttempt, 0, len(rows))
	for _, row := range rows {
		attempts = append(attempts, row.toAttempt())
	}
	return attempts, nil
}

// recordRefusedPublish stores a refused attempt with the violations that refused it.
func (s *SurrealStore) recordRefusedPublish(ctx context.Context, schemaID models.RecordID, actorID, version string, violations []registrycompat.Violation) error {
	rows := make([]map[string]any, 0, len(violations))
	for _, violation := range violations {
		rows = append(rows, map[string]any{"rule": violation.Rule, "path": violation.Path, "message": violation.Message})
	}
	_, err := queryRows[any](ctx, s.DB, `
		CREATE registry_publish SET schema = $schema, version = $version, actor = $actor,
			accepted = false, violations = $violations`,
		map[string]any{"schema": schemaID, "version": version, "actor": userRecord(actorID), "violations": rows})
	if err != nil {
		return fmt.Errorf("record refused publish: %w", err)
	}
	return nil
}
