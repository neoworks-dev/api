package database

import (
	"context"
	"fmt"
	"time"

	"github.com/surrealdb/surrealdb.go/pkg/models"
)

type Install struct {
	ID        string     `json:"id"`
	UserID    string     `json:"userId"`
	ClientID  string     `json:"clientId"`
	EncPub    string     `json:"encPub"`
	SignPub   string     `json:"signPub"`
	Name      *string    `json:"name"`
	CreatedAt time.Time  `json:"createdAt"`
	RevokedAt *time.Time `json:"revokedAt"`
}

type dbInstall struct {
	ID        *models.RecordID `json:"id"`
	User      *models.RecordID `json:"user"`
	Client    *models.RecordID `json:"client"`
	EncPub    string           `json:"enc_pub"`
	SignPub   string           `json:"sign_pub"`
	Name      *string          `json:"name"`
	CreatedAt time.Time        `json:"created_at"`
	RevokedAt *time.Time       `json:"revoked_at"`
}

func (row dbInstall) toInstall() Install {
	return Install{
		ID:        recordIDString(row.ID),
		UserID:    recordIDString(row.User),
		ClientID:  recordIDString(row.Client),
		EncPub:    row.EncPub,
		SignPub:   row.SignPub,
		Name:      row.Name,
		CreatedAt: row.CreatedAt,
		RevokedAt: row.RevokedAt,
	}
}

// Certificate is the user's signed delegation of an install; bytes and signature
// are stored and served verbatim.
type Certificate struct {
	CertID      string    `json:"certId"`
	UserID      string    `json:"userId"`
	InstallID   string    `json:"installId"`
	Certificate string    `json:"certificate"`
	Signature   string    `json:"certificateSignature"`
	CreatedAt   time.Time `json:"createdAt"`
}

type dbCertificate struct {
	ID        *models.RecordID `json:"id"`
	User      *models.RecordID `json:"user"`
	Install   *models.RecordID `json:"install"`
	Bytes     string           `json:"bytes"`
	Signature string           `json:"signature"`
	CreatedAt time.Time        `json:"created_at"`
}

func (row dbCertificate) toCertificate() Certificate {
	return Certificate{
		CertID:      recordIDString(row.ID),
		UserID:      recordIDString(row.User),
		InstallID:   recordIDString(row.Install),
		Certificate: row.Bytes,
		Signature:   row.Signature,
		CreatedAt:   row.CreatedAt,
	}
}

type CreateInstallParams struct {
	InstallID string
	UserID    string
	ClientID  string
	EncPub    string
	SignPub   string
	Name      string
}

// CreateInstall records an app installation. Registering the same installId again
// for the same user and client returns the existing row unchanged.
func (s *SurrealStore) CreateInstall(ctx context.Context, params CreateInstallParams) (*Install, error) {
	existing, err := s.GetInstall(ctx, params.InstallID)
	if err == nil {
		return existing, nil
	}
	if err != ErrNotFound {
		return nil, err
	}

	row, err := queryFirst[dbInstall](ctx, s.DB,
		`CREATE $install SET user = $user, client = $client, enc_pub = $enc_pub,
			sign_pub = $sign_pub, name = $name`,
		map[string]any{
			"install":  models.NewRecordID("install", params.InstallID),
			"user":     models.NewRecordID("user", params.UserID),
			"client":   models.NewRecordID("client", params.ClientID),
			"enc_pub":  params.EncPub,
			"sign_pub": params.SignPub,
			"name":     params.Name,
		})
	if err != nil {
		return nil, fmt.Errorf("create install: %w", err)
	}
	created := row.toInstall()
	return &created, nil
}

func (s *SurrealStore) GetInstall(ctx context.Context, installID string) (*Install, error) {
	row, err := queryFirst[dbInstall](ctx, s.DB, "SELECT * FROM $install",
		map[string]any{"install": models.NewRecordID("install", installID)})
	if err != nil {
		return nil, err
	}
	install := row.toInstall()
	return &install, nil
}

func (s *SurrealStore) ListInstalls(ctx context.Context, userID string) ([]Install, error) {
	rows, err := queryRows[dbInstall](ctx, s.DB,
		"SELECT * FROM install WHERE user = $user ORDER BY created_at ASC",
		map[string]any{"user": models.NewRecordID("user", userID)})
	if err != nil {
		return nil, fmt.Errorf("list installs: %w", err)
	}
	installs := make([]Install, 0, len(rows))
	for _, row := range rows {
		installs = append(installs, row.toInstall())
	}
	return installs, nil
}

// RevokeInstall revokes an install and everything it holds in one transaction: its
// refresh tokens stop working, each of its grants is revoked and logged, and the
// nodes it could read are flagged for key rotation. Revoking twice is harmless.
func (s *SurrealStore) RevokeInstall(ctx context.Context, userID, installID string) error {
	outcome, err := queryReturned[txOutcome](ctx, s.DB, `
		BEGIN TRANSACTION;
		LET $current = (SELECT * FROM ONLY $install WHERE user = $user);
		LET $outcome = IF $current = NONE {
			{ status: 'missing', version: 0 }
		} ELSE {
			UPDATE $install SET revoked_at = time::now() WHERE revoked_at = NONE;
			UPDATE refresh_token SET revoked = true WHERE install = $install;
			LET $grants = (SELECT VALUE id FROM access_grant
				WHERE principal_type = 'install' AND principal_id = $install_id AND revoked_at = NONE);
			FOR $grant IN $grants {
				fn::revoke_grant($grant, 'user', $user_id);
			};
			{ status: 'ok', version: 0 }
		};
		RETURN $outcome;
		COMMIT TRANSACTION;`,
		map[string]any{
			"install":    models.NewRecordID("install", installID),
			"user":       models.NewRecordID("user", userID),
			"install_id": installID,
			"user_id":    userID,
		})
	if err != nil {
		return fmt.Errorf("revoke install: %w", err)
	}
	return outcomeError(outcome)
}

type CreateCertificateParams struct {
	CertID    string
	UserID    string
	InstallID string
	Bytes     string
	Signature string
}

func (s *SurrealStore) CreateCertificate(ctx context.Context, params CreateCertificateParams) (*Certificate, error) {
	row, err := queryFirst[dbCertificate](ctx, s.DB,
		"CREATE $certificate SET user = $user, install = $install, bytes = $bytes, signature = $signature",
		map[string]any{
			"certificate": models.NewRecordID("certificate", params.CertID),
			"user":        models.NewRecordID("user", params.UserID),
			"install":     models.NewRecordID("install", params.InstallID),
			"bytes":       params.Bytes,
			"signature":   params.Signature,
		})
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	created := row.toCertificate()
	return &created, nil
}

func (s *SurrealStore) GetCertificate(ctx context.Context, certID string) (*Certificate, error) {
	row, err := queryFirst[dbCertificate](ctx, s.DB, "SELECT * FROM $certificate",
		map[string]any{"certificate": models.NewRecordID("certificate", certID)})
	if err != nil {
		return nil, err
	}
	certificate := row.toCertificate()
	return &certificate, nil
}

// LatestCertificate returns the install's newest delegation certificate.
func (s *SurrealStore) LatestCertificate(ctx context.Context, installID string) (*Certificate, error) {
	row, err := queryFirst[dbCertificate](ctx, s.DB,
		"SELECT * FROM certificate WHERE install = $install ORDER BY created_at DESC LIMIT 1",
		map[string]any{"install": models.NewRecordID("install", installID)})
	if err != nil {
		return nil, err
	}
	certificate := row.toCertificate()
	return &certificate, nil
}
