package database

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/gofrs/uuid"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// Record identifiers come back from SurrealDB in whatever shape they were
// defined with. Strings decode as strings, but a uuid id decodes as CBOR tag 37
// wrapping 16 raw bytes, and a composite id (`item:[space, item]`) as a slice of
// those — so formatting one with %v yields `{37 [195 171 …]}` rather than
// anything a client could address. These helpers render them canonically.

// recordIDString renders a record id's identifier: `user:abc` → "abc",
// `space:u'…'` → the canonical uuid. Composite ids render bracketed, which is
// for logs only — callers that mean a specific component use recordIDTail.
func recordIDString(r *models.RecordID) string {
	if r == nil {
		return ""
	}
	return identifierString(r.ID)
}

// recordIDTail renders the last component of a record id — the item uuid of an
// `item:[space, item]` key, the version uuid of an
// `item_version:[space, item, version]` key. A scalar id is its own tail.
func recordIDTail(r *models.RecordID) string {
	if r == nil {
		return ""
	}
	parts, ok := r.ID.([]any)
	if !ok {
		return identifierString(r.ID)
	}
	if len(parts) == 0 {
		return ""
	}
	return identifierString(parts[len(parts)-1])
}

// recordUUID reads a record id whose identifier is a single uuid.
func recordUUID(r *models.RecordID) (models.UUID, error) {
	if r == nil {
		return models.UUID{}, fmt.Errorf("record id is nil")
	}
	return parseUUID(identifierString(r.ID))
}

func parseUUID(value string) (models.UUID, error) {
	parsed, err := uuid.FromString(value)
	if err != nil {
		return models.UUID{}, fmt.Errorf("not a uuid: %q", value)
	}
	return models.UUID{UUID: parsed}, nil
}

func identifierString(id any) string {
	switch value := id.(type) {
	case string:
		return value
	case models.UUID:
		return value.String()
	case cbor.Tag:
		return taggedString(value)
	case []any:
		return sliceString(value)
	default:
		return fmt.Sprintf("%v", id)
	}
}

func taggedString(tag cbor.Tag) string {
	raw, ok := tag.Content.([]byte)
	if !ok {
		return fmt.Sprintf("%v", tag.Content)
	}
	parsed, err := uuid.FromBytes(raw)
	if err != nil {
		return fmt.Sprintf("%v", tag.Content)
	}
	return parsed.String()
}

func sliceString(parts []any) string {
	rendered := "["
	for i, part := range parts {
		if i > 0 {
			rendered += ", "
		}
		rendered += identifierString(part)
	}
	return rendered + "]"
}
