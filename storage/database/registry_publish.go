package database

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/surrealdb/surrealdb.go/pkg/models"
)

const (
	maxRegistryFiles      = 200
	maxRegistryTotalBytes = 2 << 20
	maxRegistryTargets    = 32
)

var (
	// ErrVersionExists means the version was already published; versions are immutable.
	ErrVersionExists = errors.New("version exists")

	registryNamePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	registryVersionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$`)
)

// RegistryPublishInput is one version of a schema as submitted by its publisher.
type RegistryPublishInput struct {
	Scope       string
	Name        string
	Version     string
	Description string
	License     string
	Repository  string
	Readme      string
	Targets     []string
	Files       []RegistryPublishFile
}

type RegistryPublishFile struct {
	Path     string `json:"path"`
	Contents string `json:"contents"`
}

func (input RegistryPublishInput) validate() error {
	if !registryNamePattern.MatchString(input.Scope) || !registryNamePattern.MatchString(input.Name) {
		return fmt.Errorf("%w: scope and name are lowercase letters, digits, '.', '_' or '-'", ErrInvalidInput)
	}
	if !registryVersionPattern.MatchString(input.Version) {
		return fmt.Errorf("%w: version must be letters, digits, '.', '+', '_' or '-'", ErrInvalidInput)
	}
	if len(input.Targets) > maxRegistryTargets {
		return fmt.Errorf("%w: too many targets", ErrInvalidInput)
	}
	return input.validateFiles()
}

func (input RegistryPublishInput) validateFiles() error {
	if len(input.Files) == 0 || len(input.Files) > maxRegistryFiles {
		return fmt.Errorf("%w: a version needs between 1 and %d files", ErrInvalidInput, maxRegistryFiles)
	}
	seen := map[string]bool{}
	total := 0
	for _, file := range input.Files {
		if file.Path == "" || strings.HasPrefix(file.Path, "/") || strings.Contains(file.Path, "..") {
			return fmt.Errorf("%w: invalid file path %q", ErrInvalidInput, file.Path)
		}
		if seen[file.Path] {
			return fmt.Errorf("%w: duplicate file path %q", ErrInvalidInput, file.Path)
		}
		seen[file.Path] = true
		total += len(file.Contents)
	}
	if total > maxRegistryTotalBytes {
		return fmt.Errorf("%w: files exceed %d bytes", ErrInvalidInput, maxRegistryTotalBytes)
	}
	return nil
}

const registryPublishStatement = `
	BEGIN TRANSACTION;
	LET $existing = (SELECT * FROM registry_schema WHERE scope = $scope AND name = $name LIMIT 1)[0];
	LET $schema = IF $existing = NONE {
		(CREATE registry_schema SET scope = $scope, name = $name, owner = $owner,
			description = $description, license = $license, repository = $repository,
			latest_version = $version)[0]
	} ELSE {
		(UPDATE $existing.id SET latest_version = $version)[0]
	};
	LET $created = (CREATE registry_schema_version SET schema = $schema.id, version = $version,
		readme = $readme, targets = $targets)[0];
	FOR $file IN $files {
		CREATE registry_schema_file SET version = $created.id, path = $file.path,
			contents = $file.contents, size = $file.size, ordinal = $file.ordinal;
	};
	RETURN [$schema];
	COMMIT TRANSACTION;`

func registryPublishParams(ownerID string, input RegistryPublishInput) map[string]any {
	files := make([]map[string]any, 0, len(input.Files))
	for ordinal, file := range input.Files {
		files = append(files, map[string]any{
			"path": file.Path, "contents": file.Contents, "size": len(file.Contents), "ordinal": ordinal,
		})
	}
	targets := input.Targets
	if targets == nil {
		targets = []string{}
	}
	return map[string]any{
		"scope": input.Scope, "name": input.Name, "owner": models.NewRecordID("user", ownerID),
		"description": input.Description, "license": input.License, "repository": input.Repository,
		"version": input.Version, "readme": input.Readme, "targets": targets, "files": files,
	}
}

// checkPublishable refuses a publish by a user who does not own an existing
// schema, and a version that already exists.
func (s *SurrealStore) checkPublishable(ctx context.Context, ownerID string, input RegistryPublishInput) error {
	row, err := s.getRegistrySchemaRow(ctx, input.Scope, input.Name)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if rowOwner, _ := row.Owner.ID.(string); rowOwner != ownerID {
		return ErrForbidden
	}
	_, err = queryFirst[dbRegistryVersion](ctx, s.DB, registryVersionStatement,
		map[string]any{"schema": row.ID, "version": input.Version})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return ErrVersionExists
}

// PublishRegistryVersion adds an immutable version. The first publish of
// `@scope/name` creates the schema owned by ownerID; later versions are accepted
// only from that owner.
func (s *SurrealStore) PublishRegistryVersion(ctx context.Context, ownerID string, input RegistryPublishInput) (*RegistrySchema, error) {
	if err := input.validate(); err != nil {
		return nil, err
	}
	if err := s.checkPublishable(ctx, ownerID, input); err != nil {
		return nil, err
	}
	rows, err := queryReturned[[]dbRegistrySchema](ctx, s.DB, registryPublishStatement,
		registryPublishParams(ownerID, input))
	if err != nil {
		// A concurrent publish may have won a unique index; report why.
		if recheck := s.checkPublishable(ctx, ownerID, input); recheck != nil {
			return nil, recheck
		}
		return nil, fmt.Errorf("publish registry version: %w", err)
	}
	if len(*rows) == 0 {
		return nil, fmt.Errorf("publish registry version: no result returned")
	}
	schema := (*rows)[0].toSchema()
	return &schema, nil
}
