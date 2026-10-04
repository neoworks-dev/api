package database

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/neoworks/auth/access"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// BlobTarget is one stored object of a node that a caller may be given URLs for.
type BlobTarget struct {
	OwnerID  string
	ObjectID string
	Chunks   int
}

// AuthorizeBlob checks that the principal may upload (write) or download (read)
// the object, and that the node's blob reference names it.
func (s *SurrealStore) AuthorizeBlob(ctx context.Context, principal access.Principal, nodeID, objectID string, upload bool) (*BlobTarget, error) {
	minimum := access.RoleRead
	if upload {
		minimum = access.RoleWrite
	}
	node, err := s.authorizeNode(ctx, principal, nodeID, minimum)
	if err != nil {
		return nil, err
	}
	return blobTarget(node, objectID)
}

// AuthorizeLinkBlob checks that the node lies in the subtree a link shares.
func (s *SurrealStore) AuthorizeLinkBlob(ctx context.Context, linkID, nodeID, objectID string) (*BlobTarget, error) {
	linked, err := s.LinkedNode(ctx, linkID)
	if err != nil {
		return nil, err
	}
	node, err := s.getNodeRow(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	if !withinSubtree(node, linked.ID) {
		return nil, ErrNotFound
	}
	return blobTarget(node, objectID)
}

func withinSubtree(node *dbNode, subtreeRoot *models.RecordID) bool {
	if recordIDString(node.ID) == recordIDString(subtreeRoot) {
		return true
	}
	for _, ancestor := range node.Ancestors {
		if recordIDString(&ancestor) == recordIDString(subtreeRoot) {
			return true
		}
	}
	return false
}

func blobTarget(node *dbNode, objectID string) (*BlobTarget, error) {
	if node.Blob == nil || node.Deleted {
		return nil, ErrNotFound
	}
	var reference BlobReference
	if err := json.Unmarshal([]byte(*node.Blob), &reference); err != nil {
		return nil, fmt.Errorf("stored blob reference: %w", err)
	}
	chunks, found := reference.ChunkCount(objectID)
	if !found {
		return nil, ErrNotFound
	}
	return &BlobTarget{OwnerID: recordIDString(node.Owner), ObjectID: objectID, Chunks: chunks}, nil
}

// StorageUsedBytes sums the stored bytes of the owner's live nodes.
func (s *SurrealStore) StorageUsedBytes(ctx context.Context, ownerID string) (int64, error) {
	totals, err := queryRows[int64](ctx, s.DB,
		"SELECT VALUE math::sum(blob_size) FROM node WHERE owner = $owner AND deleted = false GROUP ALL",
		map[string]any{"owner": models.NewRecordID("user", ownerID)})
	if err != nil {
		return 0, fmt.Errorf("storage usage: %w", err)
	}
	if len(totals) == 0 {
		return 0, nil
	}
	return totals[0], nil
}
