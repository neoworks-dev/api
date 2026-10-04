package database_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/accesslog"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
)

// renewalDevice is an authenticator device with a registered renewal certificate.
type renewalDevice struct {
	owner         access.Principal
	deviceID      string
	renewalCertID string
	key           ed25519.PrivateKey
}

func newRenewalDevice(t *testing.T, f *fixture, owner access.Principal) *renewalDevice {
	t.Helper()
	return newRenewalDeviceExpiring(t, f, owner, time.Now().Add(365*24*time.Hour))
}

func newRenewalDeviceExpiring(t *testing.T, f *fixture, owner access.Principal, expiresAt time.Time) *renewalDevice {
	t.Helper()
	ctx := context.Background()
	device, err := f.store.RegisterDevice(ctx, owner.UserID, &database.RegisterDeviceParams{Name: "phone", Kind: "authenticator"})
	if err != nil {
		t.Fatalf("register device: %v", err)
	}
	publicKey, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	renewalCertID := uuid.NewString()
	raw, err := json.Marshal(accesslog.RenewalCertificate{
		Version: 1, RenewalCertID: renewalCertID, UserID: owner.UserID, DeviceID: device.ID,
		RenewalSignPub: accesslog.Encode(publicKey), IssuedAt: time.Now(), ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := database.RegisterRenewalRequest{
		Certificate: accesslog.Encode(raw),
		Signature:   accesslog.SignRenewal(f.accountOf(owner).Key, raw),
	}
	if _, err := f.store.RegisterRenewalCertificate(ctx, owner, request); err != nil {
		t.Fatalf("register renewal certificate: %v", err)
	}
	return &renewalDevice{owner: owner, deviceID: device.ID, renewalCertID: renewalCertID, key: key}
}

// renewedRequest builds a renewal request for the install, letting the caller
// alter the certificate before it is signed.
func (device *renewalDevice) renewedRequest(t *testing.T, f *fixture, install *dbtest.Install, expiresAt time.Time, alter func(*accesslog.Certificate)) database.RenewRequest {
	t.Helper()
	stored, err := f.store.GetCertificate(context.Background(), install.CertID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64Decode(stored.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	var certificate accesslog.Certificate
	if err := json.Unmarshal(raw, &certificate); err != nil {
		t.Fatal(err)
	}
	certificate.CertID = uuid.NewString()
	certificate.OriginCertID = install.CertID
	certificate.RenewalCertID = device.renewalCertID
	certificate.IssuedAt = time.Now()
	certificate.ExpiresAt = expiresAt
	if alter != nil {
		alter(&certificate)
	}
	renewedBytes, err := json.Marshal(certificate)
	if err != nil {
		t.Fatal(err)
	}
	return database.RenewRequest{Certificate: accesslog.Encode(renewedBytes), Signature: accesslog.SignDelegation(device.key, renewedBytes)}
}

func (device *renewalDevice) renew(t *testing.T, f *fixture, install *dbtest.Install, expiresAt time.Time) *database.Certificate {
	t.Helper()
	request := device.renewedRequest(t, f, install, expiresAt, nil)
	renewed, err := f.store.RenewCertificate(context.Background(), device.owner, request)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	return renewed
}

func (device *renewalDevice) tryRenew(t *testing.T, f *fixture, install *dbtest.Install, alter func(*accesslog.Certificate)) error {
	t.Helper()
	request := device.renewedRequest(t, f, install, time.Now().Add(30*24*time.Hour), alter)
	_, err := f.store.RenewCertificate(context.Background(), device.owner, request)
	return err
}

func renewalSetup(t *testing.T) (*sharingSetup, *renewalDevice) {
	t.Helper()
	setup := newSharingSetup(t, dbtest.CertificateOptions{})
	return setup, newRenewalDevice(t, setup.f, setup.owner)
}

func TestRenewalStoresACertificateThatNamesItsOrigin(t *testing.T) {
	setup, device := renewalSetup(t)
	renewed := device.renew(t, setup.f, setup.install, time.Now().Add(30*24*time.Hour))
	latest, err := setup.f.store.LatestCertificate(context.Background(), setup.install.Principal.InstallID)
	if err != nil || latest.CertID != renewed.CertID {
		t.Fatalf("latest certificate: %v %+v", err, latest)
	}
}

func TestRenewalIsRefusedForARevokedInstall(t *testing.T) {
	setup, device := renewalSetup(t)
	if err := setup.f.store.RevokeInstall(context.Background(), setup.owner.UserID, setup.install.Principal.InstallID); err != nil {
		t.Fatal(err)
	}
	expectRefusal(t, device.tryRenew(t, setup.f, setup.install, nil), database.ErrForbidden)
}

func TestRenewalIsRefusedWhenNoGrantIsActive(t *testing.T) {
	setup, device := renewalSetup(t)
	setup.f.revoke(setup.owner, setup.root.ID, access.PrincipalTypeInstall, setup.install.Principal.InstallID)
	expectRefusal(t, device.tryRenew(t, setup.f, setup.install, nil), database.ErrForbidden)
}

func TestRenewalIsRefusedAfterTheDeviceIsRevoked(t *testing.T) {
	setup, device := renewalSetup(t)
	if err := setup.f.store.RevokeDevice(context.Background(), setup.owner.UserID, device.deviceID); err != nil {
		t.Fatal(err)
	}
	expectRefusal(t, device.tryRenew(t, setup.f, setup.install, nil), database.ErrForbidden)
	stored, err := setup.f.store.GetRenewalCertificate(context.Background(), setup.owner, device.renewalCertID)
	if err != nil || stored.RevokedAt == nil {
		t.Fatalf("revoking the device must revoke its renewal certificate: %v %+v", err, stored)
	}
}

func TestRenewalIsRefusedWithAnExpiredRenewalCertificate(t *testing.T) {
	setup := newSharingSetup(t, dbtest.CertificateOptions{})
	device := newRenewalDeviceExpiring(t, setup.f, setup.owner, time.Now().Add(time.Second))
	time.Sleep(1100 * time.Millisecond)
	expectRefusal(t, device.tryRenew(t, setup.f, setup.install, nil), database.ErrForbidden)
}

func TestRenewalIsRefusedWhenTheRenewedCertificateWidensScopes(t *testing.T) {
	setup, device := renewalSetup(t)
	err := device.tryRenew(t, setup.f, setup.install, func(certificate *accesslog.Certificate) {
		certificate.Scopes = append(certificate.Scopes, "contacts:read")
	})
	expectRefusal(t, err, database.ErrForbidden)
}

func TestRenewalIsRefusedWhenTheRenewedCertificateChangesTheInstallKey(t *testing.T) {
	setup, device := renewalSetup(t)
	err := device.tryRenew(t, setup.f, setup.install, func(certificate *accesslog.Certificate) {
		certificate.InstallSignPub = "other"
	})
	expectRefusal(t, err, database.ErrForbidden)
}

func TestRenewalIsRefusedWhenItOutlivesTheRenewalCertificate(t *testing.T) {
	setup := newSharingSetup(t, dbtest.CertificateOptions{})
	device := newRenewalDeviceExpiring(t, setup.f, setup.owner, time.Now().Add(24*time.Hour))
	expectRefusal(t, device.tryRenew(t, setup.f, setup.install, nil), database.ErrForbidden)
}

func TestRenewalIsRefusedBeyondOneCertificateLifetime(t *testing.T) {
	setup, device := renewalSetup(t)
	request := device.renewedRequest(t, setup.f, setup.install, time.Now().Add(90*24*time.Hour), nil)
	_, err := setup.f.store.RenewCertificate(context.Background(), setup.owner, request)
	expectRefusal(t, err, database.ErrInvalidInput)
}

func TestRenewalIsRefusedWhenSignedByAnotherKey(t *testing.T) {
	setup, device := renewalSetup(t)
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	request := device.renewedRequest(t, setup.f, setup.install, time.Now().Add(30*24*time.Hour), nil)
	raw, _ := base64Decode(request.Certificate)
	request.Signature = accesslog.SignDelegation(stranger, raw)
	_, err := setup.f.store.RenewCertificate(context.Background(), setup.owner, request)
	expectRefusal(t, err, database.ErrForbidden)
}

func TestRenewalByAnotherUserIsRefused(t *testing.T) {
	setup, device := renewalSetup(t)
	request := device.renewedRequest(t, setup.f, setup.install, time.Now().Add(30*24*time.Hour), nil)
	_, err := setup.f.store.RenewCertificate(context.Background(), setup.friend, request)
	expectRefusal(t, err, database.ErrForbidden)
}

func TestExpiringInstallsListsTheOnesNearExpiry(t *testing.T) {
	setup := newSharingSetup(t, dbtest.CertificateOptions{ExpiresAt: time.Now().Add(3 * 24 * time.Hour)})
	later := setup.f.accountOf(setup.owner).NewInstall(t, setup.f.store, dbtest.CertificateOptions{
		Scopes: shareScopes, ExpiresAt: time.Now().Add(20 * 24 * time.Hour),
	})
	expiring, err := setup.f.store.ListExpiringInstalls(context.Background(), setup.owner.UserID, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(expiring) != 1 || expiring[0].ID != setup.install.Principal.InstallID || expiring[0].OriginCertID != setup.install.CertID {
		t.Fatalf("expiring installs: %+v", expiring)
	}
	_ = later
}

func TestRenewalCertificateIsReadableByTheOwnerOnly(t *testing.T) {
	setup, device := renewalSetup(t)
	if _, err := setup.f.store.GetRenewalCertificate(context.Background(), setup.friend, device.renewalCertID); err == nil {
		t.Fatal("an unrelated user must not read the renewal certificate")
	}
	if _, err := setup.f.store.GetRenewalCertificate(context.Background(), setup.owner, device.renewalCertID); err != nil {
		t.Fatalf("owner read: %v", err)
	}
}

func base64Decode(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}
