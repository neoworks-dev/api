package database

import (
	"context"
	"fmt"
	"slices"

	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/accesslog"
	"github.com/neoworks/auth/utils"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// GrantInput is the grant half of a signed grant request. The signature, the
// granter and the chain position come from the accompanying log entry.
type GrantInput struct {
	PrincipalType string `json:"principalType"`
	PrincipalID   string `json:"principalId"`
	Role          string `json:"role"`
	Facets        []int  `json:"facets"`
	Epoch         int    `json:"epoch"`
	WrappedKeys   string `json:"wrappedKeys"`
}

// GrantRequest is the body of POST /nodes/{id}/grants.
type GrantRequest struct {
	Grant GrantInput      `json:"grant"`
	Entry accesslog.Entry `json:"entry"`
}

// GrantResult is the stored grant and the log entry that created it.
type GrantResult struct {
	Grant AccessGrant     `json:"grant"`
	Entry accesslog.Entry `json:"entry"`
}

func (input GrantInput) validate() error {
	if input.PrincipalType != access.PrincipalTypeUser && input.PrincipalType != access.PrincipalTypeInstall {
		return fmt.Errorf("%w: principalType must be user or install", ErrInvalidInput)
	}
	if !utils.IsLowercaseUUIDv4(input.PrincipalID) {
		return fmt.Errorf("%w: principalId must be a lowercase UUIDv4", ErrInvalidInput)
	}
	if !access.ValidRole(input.Role) {
		return fmt.Errorf("%w: role must be read or write", ErrInvalidInput)
	}
	if input.Epoch < 1 || input.WrappedKeys == "" {
		return fmt.Errorf("%w: epoch and wrappedKeys are required", ErrInvalidInput)
	}
	return input.validateFacets()
}

func (input GrantInput) validateFacets() error {
	if input.Facets == nil {
		return nil
	}
	if len(input.Facets) == 0 || len(input.Facets) > maxFacetsPerNode {
		return fmt.Errorf("%w: facets must be null or a non-empty list", ErrInvalidInput)
	}
	seenFacets := map[int]bool{}
	for _, facet := range input.Facets {
		if facet < 0 || seenFacets[facet] {
			return fmt.Errorf("%w: facets must be unique and not negative", ErrInvalidInput)
		}
		seenFacets[facet] = true
	}
	return nil
}

// checkEntryMatchesGrant requires the signed entry to describe exactly this
// grant, made by the authenticated user on this node.
func checkEntryMatchesGrant(principal access.Principal, nodeID string, input GrantInput, entry accesslog.Entry) error {
	keysHash, err := accesslog.WrappedKeysHash(input.WrappedKeys)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidInput, err)
	}
	matches := entry.Action == accesslog.ActionGrant &&
		entry.NodeID == nodeID &&
		entry.PrincipalType == input.PrincipalType &&
		entry.PrincipalID == input.PrincipalID &&
		entry.Role == input.Role &&
		slices.Equal(entry.Facets, input.Facets) &&
		entry.Epoch == input.Epoch &&
		entry.WrappedKeysHash == keysHash &&
		entry.ActorID == principal.UserID
	if !matches {
		return fmt.Errorf("%w: the log entry does not describe this grant", ErrInvalidInput)
	}
	return nil
}

// verifyEntry checks the entry's shape, its hash if given, and that the acting
// user's identity key signed it.
func (s *SurrealStore) verifyEntry(ctx context.Context, principal access.Principal, entry accesslog.Entry) (string, error) {
	if err := entry.Validate(); err != nil {
		return "", fmt.Errorf("%w: %s", ErrInvalidInput, err)
	}
	if entry.ActorID != principal.UserID {
		return "", fmt.Errorf("%w: the entry must be signed by the authenticated user", ErrInvalidInput)
	}
	bundle, err := s.GetKeyBundle(ctx, principal.UserID)
	if err != nil {
		return "", fmt.Errorf("%w: the user has no key bundle", ErrInvalidInput)
	}
	if err := entry.VerifySignature(bundle.SignPub); err != nil {
		return "", fmt.Errorf("%w: %s", ErrInvalidInput, err)
	}
	entryHash, err := entry.ComputedHash()
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrInvalidInput, err)
	}
	if entry.EntryHash != "" && entry.EntryHash != entryHash {
		return "", fmt.Errorf("%w: entryHash does not match the entry", ErrInvalidInput)
	}
	return entryHash, nil
}

type dbGrantOutcome struct {
	Status string         `json:"status"`
	Grant  *dbAccessGrant `json:"grant"`
	Head   *dbLogHead     `json:"head"`
}

type dbLogHead struct {
	Index     int64  `json:"index"`
	EntryHash string `json:"entry_hash"`
}

func (head *dbLogHead) toHead() *LogHead {
	if head == nil {
		return nil
	}
	return &LogHead{Index: head.Index, EntryHash: head.EntryHash}
}

// CreateAccessGrant appends a signed grant entry to the node's chain and stores
// the grant. Only the account (never an install) grants. The owner may grant
// anyone; a user may grant their own installs a role no higher than their own.
// The entry must extend the chain head, the grant must be sealed to the node's
// current epoch, and the entry must be signed by the acting user's identity key.
func (s *SurrealStore) CreateAccessGrant(ctx context.Context, principal access.Principal, nodeID string, request GrantRequest) (*GrantResult, error) {
	input, entry := request.Grant, request.Entry
	if principal.IsInstall() {
		return nil, ErrForbidden
	}
	if err := input.validate(); err != nil {
		return nil, err
	}
	if err := checkEntryMatchesGrant(principal, nodeID, input, entry); err != nil {
		return nil, err
	}
	node, err := s.authorizeNode(ctx, principal, nodeID, access.RoleRead)
	if err != nil {
		return nil, err
	}
	if len(principal.RolesUsable(node.Collection, input.Role)) == 0 {
		return nil, ErrForbidden
	}
	entryHash, err := s.verifyEntry(ctx, principal, entry)
	if err != nil {
		return nil, err
	}
	if err := s.checkGrantAuthority(ctx, principal, node, nodeID, input); err != nil {
		return nil, err
	}

	params := grantParams(nodeID, node, input, entry, entryHash)
	outcome, err := runWithRetry(ctx, func() (*dbGrantOutcome, error) {
		return queryReturned[dbGrantOutcome](ctx, s.DB, grantStatement(input), params)
	})
	if err != nil {
		return nil, fmt.Errorf("create grant: %w", err)
	}
	return grantResult(outcome, entry, entryHash)
}

func grantResult(outcome *dbGrantOutcome, entry accesslog.Entry, entryHash string) (*GrantResult, error) {
	switch outcome.Status {
	case StatusOK:
		entry.EntryHash = entryHash
		return &GrantResult{Grant: outcome.Grant.toGrant(), Entry: entry}, nil
	case "stale_epoch":
		return nil, ErrStaleEpoch
	case "head_moved":
		return nil, &LogHeadMovedError{Head: outcome.Head.toHead()}
	default:
		return nil, ErrForbidden
	}
}

// checkGrantAuthority applies the amendment's rules: to another user only the
// node's owner; to an install only its own user, with at most their own role.
func (s *SurrealStore) checkGrantAuthority(ctx context.Context, principal access.Principal, node *dbNode, nodeID string, input GrantInput) error {
	if input.PrincipalType == access.PrincipalTypeUser {
		return s.checkUserGrant(ctx, principal, node, input)
	}
	install, err := s.GetInstall(ctx, input.PrincipalID)
	if err != nil || install.RevokedAt != nil {
		return ErrUnknownPrincipal
	}
	if install.UserID != principal.UserID {
		return ErrForbidden
	}
	if node.OwnerID == principal.UserID {
		return nil
	}
	return s.checkDelegation(ctx, principal, node, nodeID, input)
}

func (s *SurrealStore) checkUserGrant(ctx context.Context, principal access.Principal, node *dbNode, input GrantInput) error {
	if node.OwnerID != principal.UserID {
		return ErrForbidden
	}
	if _, err := s.GetUserByID(ctx, input.PrincipalID); err != nil {
		return ErrUnknownPrincipal
	}
	return nil
}

// checkDelegation lets a user pass a share on to their own install: the grant's
// role may not exceed the user's own role on the node, and when the user only
// holds facet grants the install gets a subset of those facets.
func (s *SurrealStore) checkDelegation(ctx context.Context, principal access.Principal, node *dbNode, nodeID string, input GrantInput) error {
	own := access.Principal{UserID: principal.UserID, Scopes: principal.Scopes}
	reaches, err := s.grantsReaching(ctx, own, nodeID, node)
	if err != nil {
		return err
	}
	role, wholeNode, facets := summarizeReach(reaches)
	if role == "" || !access.RoleAtLeast(role, input.Role) {
		return ErrForbidden
	}
	if wholeNode {
		return nil
	}
	if input.Facets == nil || !isSubset(input.Facets, facets) {
		return ErrForbidden
	}
	return nil
}

// summarizeReach returns the highest role among the grants, whether any covers
// the whole node, and the union of the facets of the facet grants.
func summarizeReach(reaches []grantReach) (string, bool, []int) {
	role := ""
	wholeNode := false
	facets := []int{}
	for _, reach := range reaches {
		if access.RoleAtLeast(reach.Role, role) || role == "" {
			role = reach.Role
		}
		if reach.Facets == nil {
			wholeNode = true
		}
		facets = append(facets, reach.Facets...)
	}
	return role, wholeNode, facets
}

func isSubset(subset, superset []int) bool {
	for _, value := range subset {
		if !slices.Contains(superset, value) {
			return false
		}
	}
	return true
}

func entryParams(nodeID string, entry accesslog.Entry, entryHash string) map[string]any {
	params := map[string]any{
		"node":              models.NewRecordID("node", nodeID),
		"node_id":           nodeID,
		"index":             entry.Index,
		"prev_hash":         entry.PrevHash,
		"genesis":           accesslog.GenesisPrevHash,
		"entry_hash":        entryHash,
		"action":            entry.Action,
		"grantee_type":      entry.PrincipalType,
		"grantee_id":        entry.PrincipalID,
		"role":              entry.Role,
		"epoch":             entry.Epoch,
		"wrapped_keys_hash": entry.WrappedKeysHash,
		"actor_type":        entry.ActorType,
		"actor_id":          entry.ActorID,
		"signature":         entry.Signature,
	}
	if entry.Facets != nil {
		params["facets"] = entry.Facets
	}
	return params
}

func grantParams(nodeID string, node *dbNode, input GrantInput, entry accesslog.Entry, entryHash string) map[string]any {
	params := entryParams(nodeID, entry, entryHash)
	params["collection"] = node.Collection
	params["wrapped_keys"] = input.WrappedKeys
	params["facets_none"] = input.Facets == nil
	return params
}

// logInsert is the access_log CREATE shared by grants and revokes.
func logInsert(hasFacets bool) string {
	return `CREATE access_log SET
		node_id = $node_id, index = $index, prev_hash = $prev_hash, entry_hash = $entry_hash,
		action = $action, principal_type = $grantee_type, principal_id = $grantee_id,
		role = $role, facets = ` + optionalValue(hasFacets, "$facets") + `, epoch = $epoch,
		wrapped_keys_hash = $wrapped_keys_hash, actor_type = $actor_type, actor_id = $actor_id,
		cert_id = NONE, signature = $signature;`
}

// chainHeadChecks is the SurrealQL that reads the head and decides whether the
// submitted entry extends it.
const chainHeadChecks = `
LET $head = (SELECT index, entry_hash FROM access_log WHERE node_id = $node_id ORDER BY index DESC LIMIT 1)[0];
LET $head_ok = IF $head = NONE {
	$index = 0 AND $prev_hash = $genesis
} ELSE {
	$index = $head.index + 1 AND $prev_hash = $head.entry_hash
};`

func grantStatement(input GrantInput) string {
	facets := optionalValue(input.Facets != nil, "$facets")
	assignments := `
			role = $role, facets = ` + facets + `, epoch = $epoch, wrapped_keys = $wrapped_keys,
			granted_by_type = $actor_type, granted_by_id = $actor_id, cert_id = NONE,
			signature = $signature, log_index = $index, revoked_at = NONE`
	return `
BEGIN TRANSACTION;
LET $target = (SELECT * FROM ONLY $node);` + chainHeadChecks + `
LET $existing_grant = (SELECT * FROM ONLY access_grant
	WHERE node_id = $node_id AND principal_type = $grantee_type AND principal_id = $grantee_id);
LET $verdict = IF $target = NONE OR $target.collection != $collection {
	'forbidden'
} ELSE IF $target.epoch != $epoch {
	'stale_epoch'
} ELSE IF !$head_ok {
	'head_moved'
} ELSE {
	'ok'
};
LET $stored = IF $verdict = 'ok' {
	` + logInsert(input.Facets != nil) + `
	IF $existing_grant = NONE {
		CREATE access_grant SET node_id = $node_id, principal_type = $grantee_type, principal_id = $grantee_id, ` + assignments + `;
	} ELSE {
		UPDATE access_grant SET ` + assignments + `, seq = fn::next_seq()
			WHERE node_id = $node_id AND principal_type = $grantee_type AND principal_id = $grantee_id;
	};
	IF $existing_grant = NONE OR $existing_grant.revoked_at != NONE {
		UPDATE node SET seq = fn::next_seq()
			WHERE record::id(id) = $node_id OR ($facets_none AND $node_id IN ancestors);
	};
	(SELECT * FROM ONLY access_grant
		WHERE node_id = $node_id AND principal_type = $grantee_type AND principal_id = $grantee_id)
} ELSE {
	NONE
};
RETURN { status: $verdict, grant: $stored, head: $head };
COMMIT TRANSACTION;`
}

// RevokeAccessGrant appends a signed revoke entry and revokes the grant it
// names. The owner may revoke anyone; a user may revoke their own installs and
// their own grant. The principal's keys are flagged for rotation.
func (s *SurrealStore) RevokeAccessGrant(ctx context.Context, principal access.Principal, nodeID string, entry accesslog.Entry) (*accesslog.Entry, error) {
	if principal.IsInstall() {
		return nil, ErrForbidden
	}
	if entry.Action != accesslog.ActionRevoke || entry.NodeID != nodeID {
		return nil, fmt.Errorf("%w: the entry must be a revoke on this node", ErrInvalidInput)
	}
	node, err := s.authorizeNode(ctx, principal, nodeID, access.RoleRead)
	if err != nil {
		return nil, err
	}
	entryHash, err := s.verifyEntry(ctx, principal, entry)
	if err != nil {
		return nil, err
	}
	if err := s.checkRevokeAuthority(ctx, principal, node, entry); err != nil {
		return nil, err
	}

	params := entryParams(nodeID, entry, entryHash)
	params["collection"] = node.Collection
	outcome, err := runWithRetry(ctx, func() (*dbGrantOutcome, error) {
		return queryReturned[dbGrantOutcome](ctx, s.DB, revokeStatement(entry.Facets != nil), params)
	})
	if err != nil {
		return nil, fmt.Errorf("revoke grant: %w", err)
	}
	return revokeResult(outcome, entry, entryHash)
}

func revokeResult(outcome *dbGrantOutcome, entry accesslog.Entry, entryHash string) (*accesslog.Entry, error) {
	switch outcome.Status {
	case StatusOK:
		entry.EntryHash = entryHash
		return &entry, nil
	case "head_moved":
		return nil, &LogHeadMovedError{Head: outcome.Head.toHead()}
	case "missing":
		return nil, ErrNotFound
	default:
		return nil, ErrForbidden
	}
}

func (s *SurrealStore) checkRevokeAuthority(ctx context.Context, principal access.Principal, node *dbNode, entry accesslog.Entry) error {
	if node.OwnerID == principal.UserID {
		return nil
	}
	if entry.PrincipalType == access.PrincipalTypeUser && entry.PrincipalID == principal.UserID {
		return nil
	}
	if entry.PrincipalType != access.PrincipalTypeInstall {
		return ErrForbidden
	}
	install, err := s.GetInstall(ctx, entry.PrincipalID)
	if err != nil || install.UserID != principal.UserID {
		return ErrForbidden
	}
	return nil
}

func revokeStatement(hasFacets bool) string {
	return `
BEGIN TRANSACTION;
LET $target = (SELECT * FROM ONLY $node);` + chainHeadChecks + `
LET $grant = (SELECT * FROM ONLY access_grant
	WHERE node_id = $node_id AND principal_type = $grantee_type AND principal_id = $grantee_id
	AND revoked_at = NONE);
LET $verdict = IF $target = NONE OR $target.collection != $collection {
	'forbidden'
} ELSE IF !$head_ok {
	'head_moved'
} ELSE IF $grant = NONE {
	'missing'
} ELSE {
	'ok'
};
LET $revoked = IF $verdict = 'ok' {
	` + logInsert(hasFacets) + `
	UPDATE access_grant SET revoked_at = time::now(), seq = fn::next_seq(), log_index = $index
		WHERE node_id = $node_id AND principal_type = $grantee_type AND principal_id = $grantee_id;
	fn::flag_for_rotation($node_id, $grant.facets = NONE);
	true
} ELSE {
	false
};
RETURN { status: $verdict, head: $head };
COMMIT TRANSACTION;`
}

// ListAccessLog returns a node's chain in order to a principal that may read the node.
func (s *SurrealStore) ListAccessLog(ctx context.Context, principal access.Principal, nodeID string) ([]accesslog.Entry, error) {
	if _, err := s.authorizeNode(ctx, principal, nodeID, access.RoleRead); err != nil {
		return nil, err
	}
	rows, err := queryRows[dbAccessLog](ctx, s.DB,
		"SELECT * FROM access_log WHERE node_id = $node_id ORDER BY index ASC",
		map[string]any{"node_id": nodeID})
	if err != nil {
		return nil, fmt.Errorf("list access log: %w", err)
	}
	return logFromRows(rows), nil
}

// AccessLogHead returns the last entry of a node's chain, or nil for an empty chain.
func (s *SurrealStore) AccessLogHead(ctx context.Context, nodeID string) (*LogHead, error) {
	rows, err := queryRows[dbLogHead](ctx, s.DB,
		"SELECT index, entry_hash FROM access_log WHERE node_id = $node_id ORDER BY index DESC LIMIT 1",
		map[string]any{"node_id": nodeID})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0].toHead(), nil
}
