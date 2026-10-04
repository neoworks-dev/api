package database

import (
	"context"
	"fmt"
	"time"

	"github.com/surrealdb/surrealdb.go/pkg/models"
)

const purgeBatchSize = 500

// PurgeResult reports what one purge pass removed. UnreferencedObjects are the
// blob object ids no remaining node or version points at; the caller deletes
// their chunks from object storage.
type PurgeResult struct {
	Nodes               int
	UnreferencedObjects []string
}

type expiredTombstone struct {
	ID          *models.RecordID `json:"id"`
	OwnerID     string           `json:"owner_id"`
	Seq         int64            `json:"seq"`
	BlobObjects []string         `json:"blob_objects"`
}

// PurgeTombstones deletes tombstones older than the retention window together
// with their history, grants and links, and raises each owner's purge horizon
// to the newest seq removed so that stale cursors are told to resync.
func (s *SurrealStore) PurgeTombstones(ctx context.Context, olderThan time.Duration) (*PurgeResult, error) {
	expired, err := queryRows[expiredTombstone](ctx, s.DB, `
		SELECT id, owner_id, seq, blob_objects FROM node
		WHERE deleted = true AND deleted_at != NONE AND deleted_at < $cutoff
		LIMIT $batch`,
		map[string]any{"cutoff": time.Now().Add(-olderThan), "batch": purgeBatchSize})
	if err != nil {
		return nil, fmt.Errorf("scan tombstones: %w", err)
	}

	result := &PurgeResult{}
	candidates := map[string]bool{}
	for owner, group := range groupByOwner(expired) {
		objects, err := s.purgeOwnerTombstones(ctx, owner, group)
		if err != nil {
			return result, err
		}
		result.Nodes += len(group)
		for _, object := range objects {
			candidates[object] = true
		}
	}
	return result, s.collectUnreferenced(ctx, candidates, result)
}

func groupByOwner(expired []expiredTombstone) map[string][]expiredTombstone {
	groups := map[string][]expiredTombstone{}
	for _, tombstone := range expired {
		groups[tombstone.OwnerID] = append(groups[tombstone.OwnerID], tombstone)
	}
	return groups
}

func (s *SurrealStore) purgeOwnerTombstones(ctx context.Context, owner string, group []expiredTombstone) ([]string, error) {
	nodeRecords, nodeIDs, highestSeq := summarizeTombstones(group)
	objects, err := s.objectsOfNodes(ctx, nodeIDs)
	if err != nil {
		return nil, err
	}

	err = queryExec(ctx, s.DB, `
		BEGIN TRANSACTION;
		DELETE node_version WHERE node_id IN $node_ids;
		DELETE access_grant WHERE node_id IN $node_ids;
		DELETE link WHERE node_id IN $node_ids;
		DELETE $node_records;
		UPSERT $horizon SET user_id = $owner_id;
		UPDATE $horizon SET seq = math::max([seq, $highest_seq]);
		COMMIT TRANSACTION;`,
		map[string]any{
			"node_ids":     nodeIDs,
			"node_records": nodeRecords,
			"horizon":      models.NewRecordID("purge_horizon", owner),
			"owner_id":     owner,
			"highest_seq":  highestSeq,
		})
	if err != nil {
		return nil, fmt.Errorf("purge tombstones of %s: %w", owner, err)
	}
	return objects, nil
}

// summarizeTombstones lists the group's record ids, bare ids and highest seq.
func summarizeTombstones(group []expiredTombstone) ([]models.RecordID, []string, int64) {
	records := make([]models.RecordID, 0, len(group))
	ids := make([]string, 0, len(group))
	var highestSeq int64
	for _, tombstone := range group {
		records = append(records, *tombstone.ID)
		ids = append(ids, recordIDString(tombstone.ID))
		highestSeq = max(highestSeq, tombstone.Seq)
	}
	return records, ids, highestSeq
}

func (s *SurrealStore) objectsOfNodes(ctx context.Context, nodeIDs []string) ([]string, error) {
	lists, err := queryRows[[]string](ctx, s.DB,
		"SELECT VALUE blob_objects FROM node_version WHERE node_id IN $node_ids",
		map[string]any{"node_ids": nodeIDs})
	if err != nil {
		return nil, fmt.Errorf("collect blob objects: %w", err)
	}
	objects := []string{}
	for _, list := range lists {
		objects = append(objects, list...)
	}
	return objects, nil
}

// collectUnreferenced keeps only the candidate objects that no node or version
// references any more.
func (s *SurrealStore) collectUnreferenced(ctx context.Context, candidates map[string]bool, result *PurgeResult) error {
	for object := range candidates {
		references, err := queryRows[int](ctx, s.DB,
			"SELECT VALUE count() FROM node_version WHERE blob_objects CONTAINS $object GROUP ALL",
			map[string]any{"object": object})
		if err != nil {
			return fmt.Errorf("check object references: %w", err)
		}
		if len(references) == 0 || references[0] == 0 {
			result.UnreferencedObjects = append(result.UnreferencedObjects, object)
		}
	}
	return nil
}
