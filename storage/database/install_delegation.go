package database

import (
	"context"
	"fmt"

	"github.com/neoworks/auth/access"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

const certificateReaderProbeLimit = 25

// CertificateForPrincipal returns a delegation certificate to a principal that
// needs it: the certificate's own user, or anyone who can read a node that was
// authored under it, which is how readers verify install-authored writes.
func (s *SurrealStore) CertificateForPrincipal(ctx context.Context, principal access.Principal, certID string) (*Certificate, error) {
	certificate, err := s.GetCertificate(ctx, certID)
	if err != nil {
		return nil, err
	}
	if certificate.UserID == principal.UserID {
		return certificate, nil
	}
	authored, err := queryRows[*models.RecordID](ctx, s.DB,
		"SELECT VALUE id FROM node WHERE cert_id = $cert LIMIT $limit",
		map[string]any{"cert": certID, "limit": certificateReaderProbeLimit})
	if err != nil {
		return nil, fmt.Errorf("find nodes by certificate: %w", err)
	}
	for _, nodeRecord := range authored {
		if _, err := s.authorizeNode(ctx, principal, recordIDString(nodeRecord), access.RoleRead); err == nil {
			return certificate, nil
		}
	}
	return nil, ErrNotFound
}

// InstallGrant is what an install receives at authorization: its certificate and
// the grants made to it. The same object is served at GET /installs/me.
type InstallGrant struct {
	InstallID            string        `json:"installId"`
	CertID               string        `json:"certId"`
	Certificate          string        `json:"certificate"`
	CertificateSignature string        `json:"certificateSignature"`
	Grants               []AccessGrant `json:"grants"`
}

func (s *SurrealStore) GetInstallGrant(ctx context.Context, installID string) (*InstallGrant, error) {
	certificate, err := s.LatestCertificate(ctx, installID)
	if err != nil {
		return nil, err
	}
	rows, err := queryRows[dbAccessGrant](ctx, s.DB, `
		SELECT * FROM access_grant
		WHERE principal_type = 'install' AND principal_id = $install_id AND revoked_at = NONE
		ORDER BY seq ASC`,
		map[string]any{"install_id": installID})
	if err != nil {
		return nil, fmt.Errorf("load install grants: %w", err)
	}
	return &InstallGrant{
		InstallID:            installID,
		CertID:               certificate.CertID,
		Certificate:          certificate.Certificate,
		CertificateSignature: certificate.Signature,
		Grants:               grantsFromRows(rows),
	}, nil
}
