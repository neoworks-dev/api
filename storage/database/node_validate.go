package database

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/utils"
)

const (
	KindRoot      = "root"
	KindContainer = "container"
	KindItem      = "item"
)

// ValidatedNode is a pushed node whose shape has been checked, together with
// the facts derived from its blob reference.
type ValidatedNode struct {
	Node        Node
	BlobJSON    *string
	BlobObject  map[string]any
	BlobSize    int64
	BlobObjects []string
}

// ValidateNodeInput checks everything about a pushed node that does not need
// the database: formats, kind and parent consistency, and that the author is
// the authenticated principal.
func ValidateNodeInput(node Node, principal access.Principal) (*ValidatedNode, error) {
	if err := validateNodeIdentity(node); err != nil {
		return nil, err
	}
	if err := validateNodeKeys(node); err != nil {
		return nil, err
	}
	if err := validateContent(node); err != nil {
		return nil, err
	}
	if err := validateShortcut(node); err != nil {
		return nil, err
	}
	if err := validateAuthor(node, principal); err != nil {
		return nil, err
	}
	return withBlobFacts(node)
}

func validateNodeIdentity(node Node) error {
	if !utils.IsLowercaseUUIDv4(node.ID) {
		return errors.New("id must be a lowercase UUIDv4")
	}
	if !utils.IsLowercaseUUIDv4(node.OwnerID) {
		return errors.New("ownerId must be a lowercase UUIDv4")
	}
	if !access.IsValidCollection(node.Collection) {
		return fmt.Errorf("collection %q is not a registry path @scope/name", node.Collection)
	}
	return validateNodeParent(node)
}

func validateNodeParent(node Node) error {
	switch node.Kind {
	case KindRoot:
		if node.ParentID != nil {
			return errors.New("a root has no parent")
		}
	case KindContainer, KindItem:
		return validateParentID(node)
	default:
		return fmt.Errorf("unknown kind %q", node.Kind)
	}
	return nil
}

func validateParentID(node Node) error {
	if node.ParentID == nil {
		return errors.New("parentId is required for containers and items")
	}
	if !utils.IsLowercaseUUIDv4(*node.ParentID) || *node.ParentID == node.ID {
		return errors.New("parentId must be the UUIDv4 of another node")
	}
	return nil
}

func validateNodeKeys(node Node) error {
	if node.Epoch < 1 {
		return errors.New("epoch must be at least 1")
	}
	if node.BaseSeq < 0 {
		return errors.New("baseSeq must not be negative")
	}
	if node.Signature == "" {
		return errors.New("signature is required")
	}
	hasKey := node.WrappedKey != nil && *node.WrappedKey != ""
	if node.Kind == KindRoot && hasKey {
		return errors.New("a root carries no wrappedKey")
	}
	if node.Kind != KindRoot && !hasKey {
		return errors.New("wrappedKey is required for containers and items")
	}
	return nil
}

func validateContent(node Node) error {
	tags, err := ContentFacetTags(node.Content)
	if err != nil {
		return err
	}
	if node.Kind == KindRoot && len(tags) > 0 {
		return errors.New("a root carries no content")
	}
	return nil
}

// validateShortcut checks the parts of a shortcut that need no database: an
// item naming another item and the role it passes on, with no content or blob
// of its own.
func validateShortcut(node Node) error {
	if !node.IsShortcut() {
		if node.TargetRole != nil {
			return errors.New("targetRole is only for shortcuts")
		}
		return nil
	}
	if node.Kind != KindItem {
		return errors.New("a shortcut is an item")
	}
	if !utils.IsLowercaseUUIDv4(*node.TargetID) || *node.TargetID == node.ID {
		return errors.New("targetId must be the UUIDv4 of another node")
	}
	if node.TargetRole == nil || !access.ValidRole(*node.TargetRole) {
		return errors.New("targetRole must be read or write")
	}
	if node.Content != "" || !blobAbsent(node.Blob) {
		return errors.New("a shortcut carries no content or blob")
	}
	return nil
}

func blobAbsent(blob json.RawMessage) bool {
	return len(blob) == 0 || string(blob) == "null"
}

func validateAuthor(node Node, principal access.Principal) error {
	if node.AuthorType != principal.Type() || node.AuthorID != principal.ID() {
		return errors.New("author must be the authenticated principal")
	}
	hasCertificate := node.CertID != nil && *node.CertID != ""
	if principal.IsInstall() && !hasCertificate {
		return errors.New("certId is required for install authors")
	}
	if !principal.IsInstall() && node.CertID != nil {
		return errors.New("certId is only for install authors")
	}
	return nil
}

func withBlobFacts(node Node) (*ValidatedNode, error) {
	validated := &ValidatedNode{Node: node, BlobObjects: []string{}}
	if blobAbsent(node.Blob) {
		validated.Node.Blob = nil
		return validated, nil
	}
	reference, compact, err := ParseBlobReference(node.Blob)
	if err != nil {
		return nil, err
	}
	blobJSON := string(compact)
	validated.BlobJSON = &blobJSON
	if err := json.Unmarshal(compact, &validated.BlobObject); err != nil {
		return nil, err
	}
	validated.BlobSize = reference.TotalSize()
	validated.BlobObjects = reference.ObjectIDs()
	return validated, nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
