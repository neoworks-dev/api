package database

import (
	"errors"
	"fmt"

	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/utils"
)

const (
	maxFacetsPerNode = 64
	KindRoot         = "root"
	KindContainer    = "container"
	KindItem         = "item"
)

// ValidatedNode is a pushed node whose shape has been checked, together with
// the facts derived from its blob reference.
type ValidatedNode struct {
	Node        Node
	BlobJSON    *string
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
	if err := validateFacets(node.Content); err != nil {
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
	if !containsString(access.Collections, node.Collection) {
		return fmt.Errorf("unknown collection %q", node.Collection)
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

func validateFacets(content []FacetContent) error {
	if len(content) > maxFacetsPerNode {
		return fmt.Errorf("a node has at most %d facets", maxFacetsPerNode)
	}
	seenFacets := map[int]bool{}
	for _, facet := range content {
		if facet.Facet < 0 || seenFacets[facet.Facet] {
			return errors.New("facets must be unique and not negative")
		}
		if facet.Ciphertext == "" {
			return errors.New("facet ciphertext is required")
		}
		seenFacets[facet.Facet] = true
	}
	return nil
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
	if len(node.Blob) == 0 || string(node.Blob) == "null" {
		validated.Node.Blob = nil
		return validated, nil
	}
	reference, compact, err := ParseBlobReference(node.Blob)
	if err != nil {
		return nil, err
	}
	blobJSON := string(compact)
	validated.BlobJSON = &blobJSON
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
