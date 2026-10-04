package database

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/neoworks/auth/access"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

const (
	StatusOK        = "ok"
	StatusConflict  = "conflict"
	StatusForbidden = "forbidden"

	pushAttempts = 6
)

// PushOutcome is the result of one node write. Current is set on a conflict
// when the server holds a node the client must merge against.
type PushOutcome struct {
	ID      string
	Status  string
	Seq     int64
	Current *Node
}

func (outcome PushOutcome) MarshalJSON() ([]byte, error) {
	switch outcome.Status {
	case StatusOK:
		return json.Marshal(map[string]any{"id": outcome.ID, "status": outcome.Status, "seq": outcome.Seq})
	case StatusConflict:
		return json.Marshal(map[string]any{"id": outcome.ID, "status": outcome.Status, "current": outcome.Current})
	default:
		return json.Marshal(map[string]any{"id": outcome.ID, "status": outcome.Status})
	}
}

type dbPushOutcome struct {
	Status  string  `json:"status"`
	Seq     int64   `json:"seq"`
	Current *dbNode `json:"current"`
}

// PushNode writes one node on behalf of the principal. The authorization, the
// base_seq check and the write all happen in one transaction, so a grant revoked
// or a node changed concurrently is seen by the write.
func (s *SurrealStore) PushNode(ctx context.Context, principal access.Principal, validated *ValidatedNode) (*PushOutcome, error) {
	node := validated.Node
	writerRoles := principal.RolesUsable(node.Collection, access.RoleWrite)
	if len(writerRoles) == 0 {
		return &PushOutcome{ID: node.ID, Status: StatusForbidden}, nil
	}
	if principal.IsInstall() && !s.certificateBelongsToInstall(ctx, *node.CertID, principal.InstallID) {
		return &PushOutcome{ID: node.ID, Status: StatusForbidden}, nil
	}

	statement := pushStatement(validated)
	params := pushParams(principal, validated, writerRoles)

	raw, err := runWithRetry(ctx, func() (*dbPushOutcome, error) {
		return queryReturned[dbPushOutcome](ctx, s.DB, statement, params)
	})
	if err != nil {
		return nil, fmt.Errorf("push node: %w", err)
	}
	return outcomeFromRow(node.ID, raw), nil
}

func outcomeFromRow(nodeID string, row *dbPushOutcome) *PushOutcome {
	outcome := &PushOutcome{ID: nodeID, Status: row.Status, Seq: row.Seq}
	if row.Current != nil {
		current := row.Current.toNode()
		outcome.Current = &current
	}
	return outcome
}

func (s *SurrealStore) certificateBelongsToInstall(ctx context.Context, certID, installID string) bool {
	certificate, err := s.GetCertificate(ctx, certID)
	if err != nil {
		return false
	}
	return certificate.InstallID == installID
}

// runWithRetry retries a transaction that lost a commit race on the feed counter.
func runWithRetry[Value any](ctx context.Context, run func() (*Value, error)) (*Value, error) {
	var lastError error
	for attempt := 0; attempt < pushAttempts; attempt++ {
		value, err := run()
		if err == nil {
			return value, nil
		}
		if !isTransactionConflict(err) {
			return nil, err
		}
		lastError = err
		if err := sleepBeforeRetry(ctx, attempt); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("retries exhausted: %w", lastError)
}

func isTransactionConflict(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "conflict") || strings.Contains(message, "failed to commit")
}

func sleepBeforeRetry(ctx context.Context, attempt int) error {
	delay := time.Duration(attempt+1)*20*time.Millisecond + time.Duration(rand.Intn(20))*time.Millisecond
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(delay):
		return nil
	}
}

func pushParams(principal access.Principal, validated *ValidatedNode, writerRoles []string) map[string]any {
	node := validated.Node
	params := map[string]any{
		"node":            models.NewRecordID("node", node.ID),
		"node_id":         node.ID,
		"owner_id":        node.OwnerID,
		"has_parent":      node.ParentID != nil,
		"collection":      node.Collection,
		"kind":            node.Kind,
		"epoch":           node.Epoch,
		"content":         contentOrEmpty(node.Content),
		"blob_size":       validated.BlobSize,
		"blob_objects":    validated.BlobObjects,
		"deleted":         node.Deleted,
		"base_seq":        node.BaseSeq,
		"author_type":     node.AuthorType,
		"author_id":       node.AuthorID,
		"signature":       node.Signature,
		"principal_type":  principal.Type(),
		"principal_id":    principal.ID(),
		"writer_roles":    writerRoles,
		"may_create_root": !principal.IsInstall() && node.OwnerID == principal.UserID,
	}
	addOptionalPushParams(params, validated)
	return params
}

func addOptionalPushParams(params map[string]any, validated *ValidatedNode) {
	node := validated.Node
	if node.ParentID != nil {
		params["parent"] = models.NewRecordID("node", *node.ParentID)
		params["parent_id"] = *node.ParentID
		params["parent_id"] = *node.ParentID
	}
	if node.WrappedKey != nil {
		params["wrapped_key"] = *node.WrappedKey
	}
	if validated.BlobJSON != nil {
		params["blob_json"] = *validated.BlobJSON
		params["blob"] = validated.BlobObject
	}
	if node.CertID != nil {
		params["cert_id"] = *node.CertID
	}
}

// pushStatement builds the write transaction. Optional fields that are absent
// are assigned NONE explicitly so an update clears them.
func pushStatement(validated *ValidatedNode) string {
	node := validated.Node
	shared := []string{
		"parent_id = $target_parent_id",
		"ancestors = IF $existing != NONE AND !$reparenting { $existing.ancestors } ELSE { $new_ancestors }",
		"epoch = $epoch",
		"wrapped_key = " + optionalValue(node.WrappedKey != nil, "$wrapped_key"),
		"content = $content",
		"blob = " + optionalValue(validated.BlobJSON != nil, "$blob"),
		"blob_json = " + optionalValue(validated.BlobJSON != nil, "$blob_json"),
		"blob_size = $blob_size",
		"blob_objects = $blob_objects",
		"deleted = $deleted",
		"deleted_at = IF $deleted { time::now() } ELSE { NONE }",
		"base_seq = $base_seq",
		"author_type = $author_type",
		"author_id = $author_id",
		"cert_id = " + optionalValue(node.CertID != nil, "$cert_id"),
		"signature = $signature",
		"needs_rotation = IF $existing != NONE AND $epoch <= $existing.epoch { $existing.needs_rotation } ELSE { false }",
	}
	immutable := []string{"owner_id = $owner_id", "collection = $collection", "kind = $kind"}
	return pushPreamble + pushWrite(strings.Join(shared, ", "), strings.Join(immutable, ", "), node.WrappedKey != nil, validated.BlobJSON != nil, node.CertID != nil)
}

func optionalValue(present bool, parameter string) string {
	if present {
		return parameter
	}
	return "NONE"
}

const pushPreamble = `
BEGIN TRANSACTION;
LET $existing = (SELECT * FROM ONLY $node);
LET $parent_row = IF $has_parent { (SELECT * FROM ONLY $parent) } ELSE { NONE };
LET $target_parent_id = IF $has_parent { $parent_id } ELSE { NONE };
LET $new_ancestors = IF $parent_row != NONE { array::append($parent_row.ancestors, $parent_id) } ELSE { [] };
LET $location_ancestors = IF $existing != NONE { $existing.ancestors } ELSE { $new_ancestors };
LET $self_scope = IF $existing != NONE { [$node_id] } ELSE { [] };
LET $may_write_here = array::len((SELECT VALUE id FROM access_grant
	WHERE principal_type = $principal_type AND principal_id = $principal_id
	AND revoked_at = NONE AND role IN $writer_roles
	AND ((facets = NONE AND node_id IN $location_ancestors) OR node_id IN $self_scope))) > 0;
LET $may_write_new_parent = array::len((SELECT VALUE id FROM access_grant
	WHERE principal_type = $principal_type AND principal_id = $principal_id
	AND revoked_at = NONE AND role IN $writer_roles
	AND facets = NONE AND node_id IN $new_ancestors)) > 0;
LET $reparenting = $existing != NONE AND $existing.parent_id != $target_parent_id;
LET $parent_ok = !$has_parent OR ($parent_row != NONE
	AND $parent_row.owner_id = $owner_id AND $parent_row.collection = $collection
	AND $parent_row.kind IN ['root', 'container']);
LET $move_ok = !$reparenting OR ($parent_id != $node_id
	AND !($node_id IN $parent_row.ancestors) AND $may_write_new_parent);
LET $structure_ok = $parent_ok AND (IF $existing != NONE {
	$existing.owner_id = $owner_id AND $existing.collection = $collection
	AND $existing.kind = $kind AND $move_ok
} ELSE {
	!$has_parent OR $parent_row.deleted = false
});
LET $authorized = IF $existing != NONE {
	$may_write_here
} ELSE IF $has_parent {
	$may_write_here
} ELSE {
	$may_create_root
};
LET $verdict = IF !$authorized OR !$structure_ok {
	'forbidden'
} ELSE IF ($existing = NONE AND $base_seq != 0)
	OR ($existing != NONE AND ($existing.seq != $base_seq OR $epoch < $existing.epoch)) {
	'conflict'
} ELSE {
	'ok'
};
`

func pushWrite(shared, immutable string, hasWrappedKey, hasBlob, hasCert bool) string {
	return `
LET $written_seq = IF $verdict = 'ok' {
	IF $existing = NONE {
		CREATE $node SET ` + immutable + `, ` + shared + `;
	} ELSE {
		UPDATE $node SET ` + shared + `, seq = fn::next_seq();
	};
	LET $seq = (SELECT VALUE seq FROM ONLY $node);
	CREATE node_version SET
		node_id = $node_id, parent_id = $target_parent_id, collection = $collection, kind = $kind,
		epoch = $epoch, wrapped_key = ` + optionalValue(hasWrappedKey, "$wrapped_key") + `,
		content = $content, blob_json = ` + optionalValue(hasBlob, "$blob_json") + `,
		blob_objects = $blob_objects, deleted = $deleted, base_seq = $base_seq, seq = $seq,
		author_type = $author_type, author_id = $author_id,
		cert_id = ` + optionalValue(hasCert, "$cert_id") + `, signature = $signature;
	IF $reparenting {
		UPDATE node SET
			ancestors = array::concat($new_ancestors, array::slice(ancestors, array::len($existing.ancestors))),
			seq = fn::next_seq()
			WHERE $node_id IN ancestors;
	};
	$seq
} ELSE {
	0
};
RETURN {
	status: $verdict,
	seq: $written_seq,
	current: IF $verdict = 'conflict' { $existing } ELSE { NONE }
};
COMMIT TRANSACTION;`
}
