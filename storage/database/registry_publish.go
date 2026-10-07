package database

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/surrealdb/surrealdb.go/pkg/models"
	"golang.org/x/crypto/blake2b"
)

const (
	maxRegistryFiles            = 200
	maxRegistryTotalBytes       = 2 << 20
	maxRegistryTargets          = 32
	maxRegistryTitleRunes       = 80
	maxRegistryDescriptionRunes = 500
	maxRegistryDescriptorBytes  = 1 << 20
)

var (
	// ErrVersionExists means the version was already published; versions are immutable.
	ErrVersionExists = errors.New("version exists")

	registryNamePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	registryVersionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$`)
)

// RegistryPublishInput is one version of a schema as submitted by its publisher.
// Descriptor is empty when the schema defines no Neoworks nodes.
type RegistryPublishInput struct {
	Scope       string
	Name        string
	Version     string
	Title       string
	Description string
	License     string
	Repository  string
	Readme      string
	Targets     []string
	Files       []RegistryPublishFile
	Descriptor  string
}

type RegistryPublishFile struct {
	Path     string `json:"path"`
	Contents string `json:"contents"`
}

// DescriptorHash is base64url(BLAKE2b-256(descriptor)), the H of the node contract.
func DescriptorHash(descriptor []byte) string {
	sum := blake2b.Sum256(descriptor)
	return base64.RawURLEncoding.EncodeToString(sum[:])
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
	if err := input.validateMetadata(); err != nil {
		return err
	}
	if err := input.validateDescriptor(); err != nil {
		return err
	}
	return input.validateFiles()
}

func (input RegistryPublishInput) validateMetadata() error {
	if !isFilledText(input.Title, maxRegistryTitleRunes) {
		return fmt.Errorf("%w: title is required, at most %d characters", ErrInvalidInput, maxRegistryTitleRunes)
	}
	if !isFilledText(input.Description, maxRegistryDescriptionRunes) {
		return fmt.Errorf("%w: description is required, at most %d characters", ErrInvalidInput, maxRegistryDescriptionRunes)
	}
	return nil
}

func isFilledText(text string, maxRunes int) bool {
	return strings.TrimSpace(text) != "" && utf8.ValidString(text) && utf8.RuneCountInString(text) <= maxRunes
}

func (input RegistryPublishInput) validateDescriptor() error {
	if input.Descriptor == "" {
		return nil
	}
	if len(input.Descriptor) > maxRegistryDescriptorBytes {
		return fmt.Errorf("%w: descriptor exceeds %d bytes", ErrInvalidInput, maxRegistryDescriptorBytes)
	}
	var object map[string]any
	if err := json.Unmarshal([]byte(input.Descriptor), &object); err != nil {
		return fmt.Errorf("%w: descriptor must be a JSON object", ErrInvalidInput)
	}
	return nil
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

const registryPublishStatementTemplate = `
	BEGIN TRANSACTION;
	LET $existing = (SELECT * FROM registry_schema WHERE scope = $scope AND name = $name LIMIT 1)[0];
	LET $schema = IF $existing = NONE {
		(CREATE registry_schema SET scope = $scope, name = $name, owner = $owner,
			title = $title, description = $description, license = $license, repository = $repository,
			latest_version = $version)[0]
	} ELSE {
		(UPDATE $existing.id SET title = $title, description = $description, license = $license,
			repository = $repository, latest_version = $version)[0]
	};
	LET $created = (CREATE registry_schema_version SET %s)[0];
	FOR $file IN $files {
		CREATE registry_schema_file SET version = $created.id, path = $file.path,
			contents = $file.contents, size = $file.size, ordinal = $file.ordinal;
	};
	RETURN [$schema];
	COMMIT TRANSACTION;`

// registryPublish builds the publish statement and its parameters together; the
// descriptor fields are omitted, not set to NULL, when there is no descriptor.
func registryPublish(ownerID string, input RegistryPublishInput) (string, map[string]any) {
	assignments := []string{"schema = $schema.id", "version = $version", "readme = $readme", "targets = $targets"}
	params := map[string]any{
		"scope": input.Scope, "name": input.Name, "owner": models.NewRecordID("user", ownerID),
		"title": input.Title, "description": input.Description, "license": input.License,
		"repository": input.Repository, "version": input.Version, "readme": input.Readme,
		"targets": publishTargets(input.Targets), "files": publishFiles(input.Files),
	}
	if input.Descriptor != "" {
		assignments = append(assignments, "descriptor = $descriptor", "descriptor_hash = $descriptor_hash")
		params["descriptor"] = input.Descriptor
		params["descriptor_hash"] = DescriptorHash([]byte(input.Descriptor))
	}
	return fmt.Sprintf(registryPublishStatementTemplate, strings.Join(assignments, ", ")), params
}

func publishTargets(targets []string) []string {
	if targets == nil {
		return []string{}
	}
	return targets
}

func publishFiles(input []RegistryPublishFile) []map[string]any {
	files := make([]map[string]any, 0, len(input))
	for ordinal, file := range input {
		files = append(files, map[string]any{
			"path": file.Path, "contents": file.Contents, "size": len(file.Contents), "ordinal": ordinal,
		})
	}
	return files
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
// only from that owner and replace the schema's title, description, license and
// repository.
func (s *SurrealStore) PublishRegistryVersion(ctx context.Context, ownerID string, input RegistryPublishInput) (*RegistrySchema, error) {
	if err := input.validate(); err != nil {
		return nil, err
	}
	if err := s.checkPublishable(ctx, ownerID, input); err != nil {
		return nil, err
	}
	statement, params := registryPublish(ownerID, input)
	rows, err := queryReturned[[]dbRegistrySchema](ctx, s.DB, statement, params)
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
