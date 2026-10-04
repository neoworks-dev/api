package database

import (
	"context"
	"fmt"

	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/utils"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// GrantInput is a signed grant as submitted by the granter.
type GrantInput struct {
	PrincipalType string  `json:"principalType"`
	PrincipalID   string  `json:"principalId"`
	Role          string  `json:"role"`
	Facets        []int   `json:"facets"`
	Epoch         int     `json:"epoch"`
	WrappedKeys   string  `json:"wrappedKeys"`
	CertID        *string `json:"certId"`
	Signature     string  `json:"signature"`
}

func (input GrantInput) validate() error {
	if input.PrincipalType != access.PrincipalTypeUser && input.PrincipalType != access.PrincipalTypeInstall {
		return fmt.Errorf("%w: principalType must be user or install", ErrInvalidInput)
	}
	if !utils.IsLowercaseUUIDv4(input.PrincipalID) {
		return fmt.Errorf("%w: principalId must be a lowercase UUIDv4", ErrInvalidInput)
	}
	if !access.ValidRole(input.Role) {
		return fmt.Errorf("%w: role must be read, write or admin", ErrInvalidInput)
	}
	if input.Epoch < 1 || input.WrappedKeys == "" || input.Signature == "" {
		return fmt.Errorf("%w: epoch, wrappedKeys and signature are required", ErrInvalidInput)
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

// isOwnerBootstrap reports whether this grant is the owner giving themselves
// admin on a root, the one grant that needs no existing admin.
func (input GrantInput) isOwnerBootstrap(principal access.Principal) bool {
	return !principal.IsInstall() &&
		input.PrincipalType == access.PrincipalTypeUser &&
		input.PrincipalID == principal.UserID &&
		input.Role == access.RoleAdmin &&
		input.Facets == nil
}

type dbGrantOutcome struct {
	Status string         `json:"status"`
	Grant  *dbAccessGrant `json:"grant"`
}

// CreateAccessGrant stores a signed grant on a node. The granter needs an admin grant
// on the node or an ancestor; the one exception is the owner's first admin
// grant on their own root, which has nothing to be admin through yet. The grant
// must be sealed to the node's current epoch. The server stores the wrapped
// keys and signature as given and appends the change to access_log.
func (s *SurrealStore) CreateAccessGrant(ctx context.Context, principal access.Principal, nodeID string, input GrantInput) (*AccessGrant, error) {
	if err := input.validate(); err != nil {
		return nil, err
	}
	node, err := s.nodeForGrantChange(ctx, principal, nodeID, input.isOwnerBootstrap(principal))
	if err != nil {
		return nil, err
	}
	adminRoles := principal.RolesUsable(node.Collection, access.RoleAdmin)
	if len(adminRoles) == 0 {
		return nil, ErrForbidden
	}
	if err := s.checkGranter(ctx, principal, input); err != nil {
		return nil, err
	}
	if err := s.checkGrantee(ctx, input); err != nil {
		return nil, err
	}

	params := grantParams(principal, nodeID, node, input, adminRoles)
	outcome, err := runWithRetry(ctx, func() (*dbGrantOutcome, error) {
		return queryReturned[dbGrantOutcome](ctx, s.DB, grantStatement(input), params)
	})
	if err != nil {
		return nil, fmt.Errorf("create grant: %w", err)
	}
	return grantFromOutcome(outcome)
}

// nodeForGrantChange loads the node, hiding it from principals that cannot read
// it. The owner's first admin grant on a fresh root is the one case where the
// caller holds no grant yet.
func (s *SurrealStore) nodeForGrantChange(ctx context.Context, principal access.Principal, nodeID string, bootstrap bool) (*dbNode, error) {
	if bootstrap {
		node, err := s.getNodeRow(ctx, nodeID)
		if err == nil && node.OwnerID == principal.UserID {
			return node, nil
		}
	}
	return s.authorizeNode(ctx, principal, nodeID, access.RoleRead)
}

func grantFromOutcome(outcome *dbGrantOutcome) (*AccessGrant, error) {
	switch outcome.Status {
	case StatusOK:
		grant := outcome.Grant.toGrant()
		return &grant, nil
	case "stale_epoch":
		return nil, ErrStaleEpoch
	default:
		return nil, ErrForbidden
	}
}

func (s *SurrealStore) checkGranter(ctx context.Context, principal access.Principal, input GrantInput) error {
	if !principal.IsInstall() {
		if input.CertID != nil {
			return fmt.Errorf("%w: certId is only for install granters", ErrInvalidInput)
		}
		return nil
	}
	if input.CertID == nil || !s.certificateBelongsToInstall(ctx, *input.CertID, principal.InstallID) {
		return fmt.Errorf("%w: install granters need their delegation certId", ErrForbidden)
	}
	return nil
}

func (s *SurrealStore) checkGrantee(ctx context.Context, input GrantInput) error {
	if input.PrincipalType == access.PrincipalTypeInstall {
		install, err := s.GetInstall(ctx, input.PrincipalID)
		if err != nil || install.RevokedAt != nil {
			return ErrUnknownPrincipal
		}
		return nil
	}
	if _, err := s.GetUserByID(ctx, input.PrincipalID); err != nil {
		return ErrUnknownPrincipal
	}
	return nil
}

func grantParams(principal access.Principal, nodeID string, node *dbNode, input GrantInput, adminRoles []string) map[string]any {
	params := map[string]any{
		"node":              models.NewRecordID("node", nodeID),
		"node_id":           nodeID,
		"collection":        node.Collection,
		"owner_id":          principal.UserID,
		"grantee_type":      input.PrincipalType,
		"grantee_id":        input.PrincipalID,
		"role":              input.Role,
		"epoch":             input.Epoch,
		"wrapped_keys":      input.WrappedKeys,
		"signature":         input.Signature,
		"actor_type":        principal.Type(),
		"actor_id":          principal.ID(),
		"admin_roles":       adminRoles,
		"bootstrap_allowed": input.isOwnerBootstrap(principal),
		"facets_none":       input.Facets == nil,
	}
	if input.Facets != nil {
		params["facets"] = input.Facets
	}
	if input.CertID != nil {
		params["cert_id"] = *input.CertID
	}
	return params
}

func grantStatement(input GrantInput) string {
	facets := optionalValue(input.Facets != nil, "$facets")
	certID := optionalValue(input.CertID != nil, "$cert_id")
	assignments := `
			role = $role, facets = ` + facets + `, epoch = $epoch, wrapped_keys = $wrapped_keys,
			granted_by_type = $actor_type, granted_by_id = $actor_id, cert_id = ` + certID + `,
			signature = $signature, revoked_at = NONE`
	return `
BEGIN TRANSACTION;
LET $target = (SELECT * FROM ONLY $node);
LET $is_admin = $target != NONE AND array::len((SELECT VALUE id FROM access_grant
	WHERE principal_type = $actor_type AND principal_id = $actor_id
	AND revoked_at = NONE AND role IN $admin_roles AND facets = NONE
	AND (node_id = $node_id OR node_id IN $target.ancestors))) > 0;
LET $is_bootstrap = $bootstrap_allowed AND $target != NONE AND $target.kind = 'root'
	AND $target.owner_id = $owner_id
	AND array::len((SELECT VALUE id FROM access_grant WHERE node_id = $node_id)) = 0;
LET $existing_grant = (SELECT * FROM ONLY access_grant
	WHERE node_id = $node_id AND principal_type = $grantee_type AND principal_id = $grantee_id);
LET $verdict = IF $target = NONE OR $target.collection != $collection OR !($is_admin OR $is_bootstrap) {
	'forbidden'
} ELSE IF $target.epoch != $epoch {
	'stale_epoch'
} ELSE {
	'ok'
};
LET $stored = IF $verdict = 'ok' {
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
	CREATE access_log SET
		node_id = $node_id, action = 'grant', principal_type = $grantee_type, principal_id = $grantee_id,
		role = $role, facets = ` + facets + `, epoch = $epoch, wrapped_keys = $wrapped_keys,
		granted_by_type = $actor_type, granted_by_id = $actor_id, cert_id = ` + certID + `, signature = $signature;
	(SELECT * FROM ONLY access_grant
		WHERE node_id = $node_id AND principal_type = $grantee_type AND principal_id = $grantee_id)
} ELSE {
	NONE
};
RETURN { status: $verdict, grant: $stored };
COMMIT TRANSACTION;`
}

// RevokeAccessGrant revokes one principal's grant on a node. The caller needs admin on
// the node or an ancestor. The principal's key is flagged for rotation.
func (s *SurrealStore) RevokeAccessGrant(ctx context.Context, principal access.Principal, nodeID, principalType, principalID string) error {
	node, err := s.nodeForGrantChange(ctx, principal, nodeID, false)
	if err != nil {
		return err
	}
	adminRoles := principal.RolesUsable(node.Collection, access.RoleAdmin)
	if len(adminRoles) == 0 {
		return ErrForbidden
	}
	params := map[string]any{
		"node":         models.NewRecordID("node", nodeID),
		"node_id":      nodeID,
		"collection":   node.Collection,
		"grantee_type": principalType,
		"grantee_id":   principalID,
		"actor_type":   principal.Type(),
		"actor_id":     principal.ID(),
		"admin_roles":  adminRoles,
	}
	outcome, err := runWithRetry(ctx, func() (*txOutcome, error) {
		return queryReturned[txOutcome](ctx, s.DB, revokeGrantStatement, params)
	})
	if err != nil {
		return fmt.Errorf("revoke grant: %w", err)
	}
	return revokeOutcomeError(outcome)
}

func revokeOutcomeError(outcome *txOutcome) error {
	switch outcome.Status {
	case StatusOK:
		return nil
	case StatusForbidden:
		return ErrForbidden
	default:
		return ErrNotFound
	}
}

const revokeGrantStatement = `
BEGIN TRANSACTION;
LET $target = (SELECT * FROM ONLY $node);
LET $is_admin = $target != NONE AND array::len((SELECT VALUE id FROM access_grant
	WHERE principal_type = $actor_type AND principal_id = $actor_id
	AND revoked_at = NONE AND role IN $admin_roles AND facets = NONE
	AND (node_id = $node_id OR node_id IN $target.ancestors))) > 0;
LET $grant = (SELECT VALUE id FROM ONLY access_grant
	WHERE node_id = $node_id AND principal_type = $grantee_type AND principal_id = $grantee_id);
LET $outcome = IF $target = NONE OR $target.collection != $collection OR !$is_admin {
	{ status: 'forbidden', version: 0 }
} ELSE IF $grant = NONE {
	{ status: 'missing', version: 0 }
} ELSE {
	fn::revoke_grant($grant, $actor_type, $actor_id);
	{ status: 'ok', version: 0 }
};
RETURN $outcome;
COMMIT TRANSACTION;`
