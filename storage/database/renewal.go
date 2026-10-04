package database

import (
	"context"
	"fmt"
	"time"

	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/accesslog"
	"github.com/neoworks/auth/utils"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// maxRenewedLifetime caps how far ahead a renewal key may extend a certificate:
// the 30-day lifetime of amendment 3 plus a day of clock slack.
const maxRenewedLifetime = 31 * 24 * time.Hour

// RenewalCertificate is the user's signed authorisation of one authenticator
// device to extend delegation certificates; bytes and signature are served verbatim.
type RenewalCertificate struct {
	RenewalCertID string     `json:"renewalCertId"`
	UserID        string     `json:"userId"`
	DeviceID      string     `json:"deviceId"`
	Certificate   string     `json:"renewalCertificate"`
	Signature     string     `json:"renewalCertificateSignature"`
	ExpiresAt     time.Time  `json:"expiresAt"`
	CreatedAt     time.Time  `json:"createdAt"`
	RevokedAt     *time.Time `json:"revokedAt"`
}

type dbRenewalCertificate struct {
	ID        *models.RecordID `json:"id"`
	User      *models.RecordID `json:"user"`
	Device    *models.RecordID `json:"device"`
	Bytes     string           `json:"bytes"`
	Signature string           `json:"signature"`
	ExpiresAt time.Time        `json:"expires_at"`
	CreatedAt time.Time        `json:"created_at"`
	RevokedAt *time.Time       `json:"revoked_at"`
}

func (row dbRenewalCertificate) toRenewalCertificate() RenewalCertificate {
	return RenewalCertificate{
		RenewalCertID: recordIDString(row.ID),
		UserID:        recordIDString(row.User),
		DeviceID:      recordIDString(row.Device),
		Certificate:   row.Bytes,
		Signature:     row.Signature,
		ExpiresAt:     row.ExpiresAt,
		CreatedAt:     row.CreatedAt,
		RevokedAt:     row.RevokedAt,
	}
}

// RegisterRenewalRequest is the body that stores a renewal certificate.
type RegisterRenewalRequest struct {
	Certificate string `json:"renewalCertificate"`
	Signature   string `json:"renewalCertificateSignature"`
}

// RenewRequest is the body of POST /certificates/renew.
type RenewRequest struct {
	Certificate string `json:"certificate"`
	Signature   string `json:"certificateSignature"`
}

// RegisterRenewalCertificate stores a renewal certificate for one of the user's
// authenticator devices after checking the user's identity key signed it.
func (s *SurrealStore) RegisterRenewalCertificate(ctx context.Context, principal access.Principal, request RegisterRenewalRequest) (*RenewalCertificate, error) {
	if principal.IsInstall() {
		return nil, ErrForbidden
	}
	bundle, err := s.GetKeyBundle(ctx, principal.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: the user has no key bundle", ErrInvalidInput)
	}
	renewal, err := accesslog.VerifyRenewalCertificate(request.Certificate, request.Signature, bundle.SignPub, time.Now())
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidInput, err)
	}
	if err := s.checkRenewalDevice(ctx, principal.UserID, renewal); err != nil {
		return nil, err
	}
	row, err := queryFirst[dbRenewalCertificate](ctx, s.DB, `
		CREATE $renewal SET user = $user, device = $device, bytes = $bytes,
			signature = $signature, expires_at = $expires_at`,
		map[string]any{
			"renewal":    models.NewRecordID("renewal_certificate", renewal.RenewalCertID),
			"user":       models.NewRecordID("user", principal.UserID),
			"device":     models.NewRecordID("device", renewal.DeviceID),
			"bytes":      request.Certificate,
			"signature":  request.Signature,
			"expires_at": renewal.ExpiresAt,
		})
	if err != nil {
		return nil, fmt.Errorf("store renewal certificate: %w", err)
	}
	created := row.toRenewalCertificate()
	return &created, nil
}

func (s *SurrealStore) checkRenewalDevice(ctx context.Context, userID string, renewal *accesslog.RenewalCertificate) error {
	if renewal.UserID != userID || !utils.IsLowercaseUUIDv4(renewal.RenewalCertID) {
		return fmt.Errorf("%w: the renewal certificate is not this user's", ErrInvalidInput)
	}
	device, err := s.getDevice(ctx, userID, renewal.DeviceID)
	if err != nil || device.RevokedAt != nil || device.Kind != "authenticator" {
		return fmt.Errorf("%w: the device is not an active authenticator", ErrInvalidInput)
	}
	return nil
}

// GetRenewalCertificate returns a renewal certificate to its user, or to a
// principal that can read a node authored under a certificate it signed, which
// is how readers verify renewed certificates.
func (s *SurrealStore) GetRenewalCertificate(ctx context.Context, principal access.Principal, renewalCertID string) (*RenewalCertificate, error) {
	row, err := queryFirst[dbRenewalCertificate](ctx, s.DB, "SELECT * FROM $renewal",
		map[string]any{"renewal": models.NewRecordID("renewal_certificate", renewalCertID)})
	if err != nil {
		return nil, err
	}
	renewal := row.toRenewalCertificate()
	if renewal.UserID == principal.UserID {
		return &renewal, nil
	}
	certificateIDs, err := queryRows[*models.RecordID](ctx, s.DB,
		"SELECT VALUE id FROM certificate WHERE renewal_cert_id = $renewal_cert_id",
		map[string]any{"renewal_cert_id": renewalCertID})
	if err != nil {
		return nil, fmt.Errorf("find renewed certificates: %w", err)
	}
	for _, certificateID := range certificateIDs {
		if _, err := s.CertificateForPrincipal(ctx, principal, recordIDString(certificateID)); err == nil {
			return &renewal, nil
		}
	}
	return nil, ErrNotFound
}

// RenewCertificate stores a renewed delegation certificate signed by an
// authenticator's renewal key. It refuses when the renewal certificate expired
// or its device was revoked, the install is revoked, none of the install's
// grants are active, the certificate fails verification against its origin, or
// it reaches further ahead than one certificate lifetime.
func (s *SurrealStore) RenewCertificate(ctx context.Context, principal access.Principal, request RenewRequest) (*Certificate, error) {
	if principal.IsInstall() {
		return nil, ErrForbidden
	}
	now := time.Now()
	renewed, err := s.verifiedRenewedCertificate(ctx, principal.UserID, request, now)
	if err != nil {
		return nil, err
	}
	if renewed.ExpiresAt.Sub(now) > maxRenewedLifetime || !utils.IsLowercaseUUIDv4(renewed.CertID) {
		return nil, fmt.Errorf("%w: the certificate lifetime or id is not allowed", ErrInvalidInput)
	}
	if err := s.checkInstallRenewable(ctx, principal.UserID, renewed.InstallID); err != nil {
		return nil, err
	}
	return s.storeRenewedCertificate(ctx, principal.UserID, request, renewed)
}

func (s *SurrealStore) verifiedRenewedCertificate(ctx context.Context, userID string, request RenewRequest, now time.Time) (*accesslog.Certificate, error) {
	originCertID, renewalCertID, err := accesslog.PeekRenewalLinks(request.Certificate)
	if err != nil || originCertID == "" || renewalCertID == "" {
		return nil, fmt.Errorf("%w: the certificate must name its origin and renewal certificate", ErrInvalidInput)
	}
	bundle, err := s.GetKeyBundle(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: the user has no key bundle", ErrInvalidInput)
	}
	renewal, err := s.activeRenewal(ctx, userID, renewalCertID, bundle.SignPub, now)
	if err != nil {
		return nil, err
	}
	origin, err := s.verifiedOrigin(ctx, userID, originCertID, bundle.SignPub)
	if err != nil {
		return nil, err
	}
	renewed, err := accesslog.VerifyRenewedCertificate(request.Certificate, request.Signature, renewal, origin, now)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrForbidden, err)
	}
	return renewed, nil
}

// activeRenewal loads a renewal certificate and requires it to be verified,
// unexpired, unrevoked and bound to a device that is not revoked.
func (s *SurrealStore) activeRenewal(ctx context.Context, userID, renewalCertID, userSignPub string, now time.Time) (*accesslog.RenewalCertificate, error) {
	row, err := queryFirst[dbRenewalCertificate](ctx, s.DB, "SELECT * FROM $renewal WHERE user = $user",
		map[string]any{
			"renewal": models.NewRecordID("renewal_certificate", renewalCertID),
			"user":    models.NewRecordID("user", userID),
		})
	if err != nil {
		return nil, ErrForbidden
	}
	stored := row.toRenewalCertificate()
	if stored.RevokedAt != nil {
		return nil, fmt.Errorf("%w: the renewal certificate was revoked", ErrForbidden)
	}
	renewal, err := accesslog.VerifyRenewalCertificate(stored.Certificate, stored.Signature, userSignPub, now)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrForbidden, err)
	}
	device, err := s.getDevice(ctx, userID, stored.DeviceID)
	if err != nil || device.RevokedAt != nil {
		return nil, fmt.Errorf("%w: the renewal device was revoked", ErrForbidden)
	}
	return renewal, nil
}

// verifiedOrigin loads an identity-signed certificate for the user and checks
// its signature. Its own expiry does not matter: renewals outlive it.
func (s *SurrealStore) verifiedOrigin(ctx context.Context, userID, originCertID, userSignPub string) (*accesslog.Certificate, error) {
	stored, err := s.GetCertificate(ctx, originCertID)
	if err != nil || stored.UserID != userID {
		return nil, ErrForbidden
	}
	origin, err := accesslog.VerifyOriginCertificate(stored.Certificate, stored.Signature, userSignPub)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrForbidden, err)
	}
	return origin, nil
}

func (s *SurrealStore) checkInstallRenewable(ctx context.Context, userID, installID string) error {
	install, err := s.GetInstall(ctx, installID)
	if err != nil || install.UserID != userID || install.RevokedAt != nil {
		return fmt.Errorf("%w: the install is revoked", ErrForbidden)
	}
	active, err := queryRows[*models.RecordID](ctx, s.DB, `
		SELECT VALUE id FROM access_grant
		WHERE principal_type = 'install' AND principal_id = $install_id AND revoked_at = NONE LIMIT 1`,
		map[string]any{"install_id": installID})
	if err != nil {
		return fmt.Errorf("load install grants: %w", err)
	}
	if len(active) == 0 {
		return fmt.Errorf("%w: none of the install's grants are active", ErrForbidden)
	}
	return nil
}

func (s *SurrealStore) storeRenewedCertificate(ctx context.Context, userID string, request RenewRequest, renewed *accesslog.Certificate) (*Certificate, error) {
	row, err := queryFirst[dbCertificate](ctx, s.DB, `
		CREATE $certificate SET user = $user, install = $install, bytes = $bytes, signature = $signature,
			origin_cert_id = $origin_cert_id, renewal_cert_id = $renewal_cert_id`,
		map[string]any{
			"certificate":     models.NewRecordID("certificate", renewed.CertID),
			"user":            models.NewRecordID("user", userID),
			"install":         models.NewRecordID("install", renewed.InstallID),
			"bytes":           request.Certificate,
			"signature":       request.Signature,
			"origin_cert_id":  renewed.OriginCertID,
			"renewal_cert_id": renewed.RenewalCertID,
		})
	if err != nil {
		return nil, fmt.Errorf("store renewed certificate: %w", err)
	}
	created := row.toCertificate()
	return &created, nil
}

// verifiedCertificate verifies a stored delegation certificate: identity-signed
// ones against the user's key, renewed ones through their renewal certificate
// and identity-signed origin.
func (s *SurrealStore) verifiedCertificate(ctx context.Context, stored *Certificate, now time.Time) (*accesslog.Certificate, error) {
	originCertID, renewalCertID, err := accesslog.PeekRenewalLinks(stored.Certificate)
	if err != nil {
		return nil, err
	}
	bundle, err := s.GetKeyBundle(ctx, stored.UserID)
	if err != nil {
		return nil, fmt.Errorf("the user has no key bundle")
	}
	if renewalCertID == "" {
		return accesslog.VerifyIdentityCertificate(stored.Certificate, stored.Signature, bundle.SignPub, now)
	}
	renewalRow, err := queryFirst[dbRenewalCertificate](ctx, s.DB, "SELECT * FROM $renewal",
		map[string]any{"renewal": models.NewRecordID("renewal_certificate", renewalCertID)})
	if err != nil {
		return nil, fmt.Errorf("unknown renewal certificate")
	}
	renewalStored := renewalRow.toRenewalCertificate()
	renewal, err := accesslog.VerifyRenewalCertificate(renewalStored.Certificate, renewalStored.Signature, bundle.SignPub, now)
	if err != nil {
		return nil, err
	}
	origin, err := s.verifiedOrigin(ctx, stored.UserID, originCertID, bundle.SignPub)
	if err != nil {
		return nil, fmt.Errorf("unusable origin certificate")
	}
	return accesslog.VerifyRenewedCertificate(stored.Certificate, stored.Signature, renewal, origin, now)
}

// ExpiringInstall is an active install with its newest certificate, which the
// authenticator renews when it nears expiry.
type ExpiringInstall struct {
	Install
	CertID               string    `json:"certId"`
	OriginCertID         string    `json:"originCertId"`
	Certificate          string    `json:"certificate"`
	CertificateSignature string    `json:"certificateSignature"`
	CertificateExpiresAt time.Time `json:"certificateExpiresAt"`
}

// ListExpiringInstalls lists the user's active installs whose newest
// certificate expires within the window.
func (s *SurrealStore) ListExpiringInstalls(ctx context.Context, userID string, window time.Duration) ([]ExpiringInstall, error) {
	installs, err := s.ListInstalls(ctx, userID)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(window)
	expiring := []ExpiringInstall{}
	for _, install := range installs {
		entry, found := s.expiringEntry(ctx, install, deadline)
		if found {
			expiring = append(expiring, entry)
		}
	}
	return expiring, nil
}

func (s *SurrealStore) expiringEntry(ctx context.Context, install Install, deadline time.Time) (ExpiringInstall, bool) {
	if install.RevokedAt != nil {
		return ExpiringInstall{}, false
	}
	certificate, err := s.LatestCertificate(ctx, install.ID)
	if err != nil {
		return ExpiringInstall{}, false
	}
	expiresAt, originCertID, err := accesslog.PeekExpiry(certificate.Certificate)
	if err != nil || expiresAt.After(deadline) {
		return ExpiringInstall{}, false
	}
	if originCertID == "" {
		originCertID = certificate.CertID
	}
	return ExpiringInstall{
		Install: install, CertID: certificate.CertID, OriginCertID: originCertID,
		Certificate: certificate.Certificate, CertificateSignature: certificate.Signature,
		CertificateExpiresAt: expiresAt,
	}, true
}
