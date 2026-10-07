package database

import (
	"context"
	"fmt"
	"time"

	"github.com/surrealdb/surrealdb.go/pkg/models"
)

const (
	defaultRegistryLimit = 50
	maxRegistryLimit     = 200
)

// RegistrySchema is a published schema's current state: `@scope/name`, its owner
// and the most recently published version.
type RegistrySchema struct {
	Scope          string    `json:"scope"`
	Name           string    `json:"name"`
	OwnerID        string    `json:"ownerId"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	Tags           []string  `json:"tags"`
	License        string    `json:"license"`
	Repository     string    `json:"repository"`
	LatestVersion  string    `json:"latestVersion"`
	Official       bool      `json:"official"`
	DownloadsTotal int       `json:"downloadsTotal"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// RegistryFile is one source file of a published version.
type RegistryFile struct {
	Path     string `json:"path"`
	Contents string `json:"contents"`
	Size     int    `json:"size"`
	Ordinal  int    `json:"ordinal"`
}

// RegistryVersion is an immutable release. Files is filled only when a single
// version is read. DescriptorHash is set when the version defines Neoworks nodes.
type RegistryVersion struct {
	Version        string         `json:"version"`
	State          string         `json:"state"`
	Readme         string         `json:"readme"`
	Targets        []string       `json:"targets"`
	DescriptorHash string         `json:"descriptorHash,omitempty"`
	ReleasedAt     time.Time      `json:"releasedAt"`
	CreatedAt      time.Time      `json:"createdAt"`
	Files          []RegistryFile `json:"files,omitempty"`
}

type dbRegistrySchema struct {
	ID             models.RecordID `json:"id"`
	Scope          string          `json:"scope"`
	Name           string          `json:"name"`
	Owner          models.RecordID `json:"owner"`
	Title          string          `json:"title"`
	Description    string          `json:"description"`
	Tags           []string        `json:"tags"`
	License        string          `json:"license"`
	Repository     string          `json:"repository"`
	LatestVersion  string          `json:"latest_version"`
	Official       bool            `json:"official"`
	DownloadsTotal int             `json:"downloads_total"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

func (row dbRegistrySchema) toSchema() RegistrySchema {
	ownerID, _ := row.Owner.ID.(string)
	tags := row.Tags
	if tags == nil {
		tags = []string{}
	}
	return RegistrySchema{
		Scope: row.Scope, Name: row.Name, OwnerID: ownerID, Title: row.Title, Description: row.Description,
		Tags: tags, License: row.License, Repository: row.Repository, LatestVersion: row.LatestVersion,
		Official: row.Official, DownloadsTotal: row.DownloadsTotal,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
}

type dbRegistryVersion struct {
	ID             models.RecordID `json:"id"`
	Version        string          `json:"version"`
	State          string          `json:"state"`
	Readme         string          `json:"readme"`
	Targets        []string        `json:"targets"`
	DescriptorHash *string         `json:"descriptor_hash"`
	ReleasedAt     time.Time       `json:"released_at"`
	CreatedAt      time.Time       `json:"created_at"`
}

func (row dbRegistryVersion) toVersion() RegistryVersion {
	targets := row.Targets
	if targets == nil {
		targets = []string{}
	}
	version := RegistryVersion{
		Version: row.Version, State: row.State, Readme: row.Readme, Targets: targets,
		ReleasedAt: row.ReleasedAt, CreatedAt: row.CreatedAt,
	}
	if row.DescriptorHash != nil {
		version.DescriptorHash = *row.DescriptorHash
	}
	return version
}

// Version reads leave out the descriptor itself; it is served on its own by hash.
const registryVersionFields = "id, version, state, readme, targets, descriptor_hash, released_at, created_at"

const (
	registryListStatement   = "SELECT * FROM registry_schema ORDER BY updated_at DESC LIMIT $limit"
	registrySearchStatement = `SELECT *, search::score(0) + search::score(1) + search::score(2) AS relevance
		FROM registry_schema WHERE name @0@ $query OR title @1@ $query OR description @2@ $query
		ORDER BY relevance DESC LIMIT $limit`
	registryGetStatement        = "SELECT * FROM registry_schema WHERE scope = $scope AND name = $name LIMIT 1"
	registryVersionsStatement   = "SELECT " + registryVersionFields + " FROM registry_schema_version WHERE schema = $schema ORDER BY created_at DESC"
	registryVersionStatement    = "SELECT " + registryVersionFields + " FROM registry_schema_version WHERE schema = $schema AND version = $version LIMIT 1"
	registryFilesStatement      = "SELECT * FROM registry_schema_file WHERE version = $version ORDER BY ordinal"
	registryDescriptorStatement = "SELECT VALUE descriptor FROM registry_schema_version WHERE schema = $schema AND descriptor_hash = $hash LIMIT 1"
)

// ListRegistrySchemas returns schemas newest-updated first, or ranked by
// full-text relevance over name, title and description when query is not empty.
func (s *SurrealStore) ListRegistrySchemas(ctx context.Context, query string, limit int) ([]RegistrySchema, error) {
	statement := registryListStatement
	params := map[string]any{"limit": clampRegistryLimit(limit)}
	if query != "" {
		statement = registrySearchStatement
		params["query"] = query
	}
	rows, err := queryRows[dbRegistrySchema](ctx, s.DB, statement, params)
	if err != nil {
		return nil, fmt.Errorf("list registry schemas: %w", err)
	}
	schemas := make([]RegistrySchema, 0, len(rows))
	for _, row := range rows {
		schemas = append(schemas, row.toSchema())
	}
	return schemas, nil
}

func clampRegistryLimit(limit int) int {
	if limit < 1 {
		return defaultRegistryLimit
	}
	if limit > maxRegistryLimit {
		return maxRegistryLimit
	}
	return limit
}

func (s *SurrealStore) getRegistrySchemaRow(ctx context.Context, scope, name string) (*dbRegistrySchema, error) {
	return queryFirst[dbRegistrySchema](ctx, s.DB, registryGetStatement,
		map[string]any{"scope": scope, "name": name})
}

func (s *SurrealStore) GetRegistrySchema(ctx context.Context, scope, name string) (*RegistrySchema, error) {
	row, err := s.getRegistrySchemaRow(ctx, scope, name)
	if err != nil {
		return nil, err
	}
	schema := row.toSchema()
	return &schema, nil
}

// ListRegistryVersions returns a schema's versions, newest first.
func (s *SurrealStore) ListRegistryVersions(ctx context.Context, scope, name string) ([]RegistryVersion, error) {
	schemaRow, err := s.getRegistrySchemaRow(ctx, scope, name)
	if err != nil {
		return nil, err
	}
	rows, err := queryRows[dbRegistryVersion](ctx, s.DB, registryVersionsStatement,
		map[string]any{"schema": schemaRow.ID})
	if err != nil {
		return nil, fmt.Errorf("list registry versions: %w", err)
	}
	versions := make([]RegistryVersion, 0, len(rows))
	for _, row := range rows {
		versions = append(versions, row.toVersion())
	}
	return versions, nil
}

// GetRegistryVersion returns one version with its files in ordinal order.
func (s *SurrealStore) GetRegistryVersion(ctx context.Context, scope, name, version string) (*RegistryVersion, error) {
	schemaRow, err := s.getRegistrySchemaRow(ctx, scope, name)
	if err != nil {
		return nil, err
	}
	versionRow, err := queryFirst[dbRegistryVersion](ctx, s.DB, registryVersionStatement,
		map[string]any{"schema": schemaRow.ID, "version": version})
	if err != nil {
		return nil, err
	}
	files, err := queryRows[RegistryFile](ctx, s.DB, registryFilesStatement,
		map[string]any{"version": versionRow.ID})
	if err != nil {
		return nil, fmt.Errorf("list registry files: %w", err)
	}
	result := versionRow.toVersion()
	result.Files = files
	return &result, nil
}

// GetRegistryDescriptor returns the descriptor a version of `@scope/name` was published
// with, found by its hash, or ErrNotFound when no version carries it.
func (s *SurrealStore) GetRegistryDescriptor(ctx context.Context, scope, name, hash string) (string, error) {
	schemaRow, err := s.getRegistrySchemaRow(ctx, scope, name)
	if err != nil {
		return "", err
	}
	descriptor, err := queryFirst[string](ctx, s.DB, registryDescriptorStatement,
		map[string]any{"schema": schemaRow.ID, "hash": hash})
	if err != nil {
		return "", err
	}
	return *descriptor, nil
}
