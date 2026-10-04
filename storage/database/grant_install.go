package database

import (
	"context"
	"fmt"
	"time"

	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/accesslog"
)

// checkInstallGrant applies the authority rules for a grant an install signs:
// the install's delegation must allow sharing the node's collection, the grantee
// must be another existing user, and the role and facets stay within what the
// install itself holds on the node.
func (s *SurrealStore) checkInstallGrant(ctx context.Context, principal access.Principal, node *dbNode, nodeID string, request GrantRequest) error {
	input := request.Grant
	if input.PrincipalType != access.PrincipalTypeUser {
		return ErrForbidden
	}
	certificate, err := s.checkInstallDelegation(ctx, principal, node, request.Entry)
	if err != nil {
		return err
	}
	if input.Role == access.RoleWrite && !certificate.HasScope(node.Collection+":write") {
		return fmt.Errorf("%w: the certificate does not allow writing %s", ErrForbidden, node.Collection)
	}
	if _, err := s.GetUserByID(ctx, input.PrincipalID); err != nil {
		return ErrUnknownPrincipal
	}
	return s.checkDelegation(ctx, principal, node, nodeID, input)
}

// checkInstallShare applies the same delegation rules to a revoke entry, which
// has no role to bound.
func (s *SurrealStore) checkInstallShare(ctx context.Context, principal access.Principal, node *dbNode, entry accesslog.Entry) error {
	_, err := s.checkInstallDelegation(ctx, principal, node, entry)
	return err
}

// checkInstallDelegation verifies everything about an install actor that does
// not depend on the entry's content: the install is live, the certificate it
// names is its own and verifies, the owner issued it and it lists the share scope.
func (s *SurrealStore) checkInstallDelegation(ctx context.Context, principal access.Principal, node *dbNode, entry accesslog.Entry) (*accesslog.Certificate, error) {
	install, err := s.GetInstall(ctx, principal.InstallID)
	if err != nil || install.RevokedAt != nil || install.UserID != principal.UserID {
		return nil, ErrForbidden
	}
	stored, err := s.GetCertificate(ctx, *entry.CertID)
	if err != nil || stored.InstallID != install.ID || stored.UserID != principal.UserID {
		return nil, ErrForbidden
	}
	certificate, err := s.verifiedCertificate(ctx, stored, time.Now())
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrForbidden, err)
	}
	if certificate.UserID != node.OwnerID || certificate.InstallSignPub != install.SignPub {
		return nil, fmt.Errorf("%w: the certificate does not delegate this owner's install", ErrForbidden)
	}
	if !certificate.HasScope(node.Collection+":share") || !principal.CanShare(node.Collection) {
		return nil, fmt.Errorf("%w: the certificate does not allow sharing %s", ErrForbidden, node.Collection)
	}
	return certificate, nil
}
