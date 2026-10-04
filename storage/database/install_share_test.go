package database_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
)

var shareScopes = []string{"calendar:read", "calendar:write", "calendar:share"}

// sharingSetup is an owner with a calendar root and an install the owner
// granted write on it.
type sharingSetup struct {
	f       *fixture
	owner   access.Principal
	friend  access.Principal
	root    database.Node
	install *dbtest.Install
}

func newSharingSetup(t *testing.T, options dbtest.CertificateOptions) *sharingSetup {
	t.Helper()
	f := newFixture(t)
	owner := f.createUser()
	friend := f.createUser()
	root := f.createRoot(owner, "calendar")
	if options.ExpiresAt.IsZero() {
		options.ExpiresAt = time.Now().Add(30 * 24 * time.Hour)
	}
	if options.Scopes == nil {
		options.Scopes = shareScopes
	}
	install := f.accountOf(owner).NewInstall(t, f.store, options)
	f.grant(owner, root.ID, writeGrant(access.PrincipalTypeInstall, install.Principal.InstallID, 1))
	return &sharingSetup{f: f, owner: owner, friend: friend, root: root, install: install}
}

func (setup *sharingSetup) shareWith(input database.GrantInput) (*database.GrantResult, error) {
	request := setup.install.GrantRequest(setup.f.t, setup.f.store, setup.root.ID, input)
	return setup.f.store.CreateAccessGrant(context.Background(), setup.install.Principal, setup.root.ID, request)
}

func (setup *sharingSetup) friendGrant(role string) database.GrantInput {
	input := dbtest.ReadGrant(access.PrincipalTypeUser, setup.friend.UserID, 1)
	input.Role = role
	return input
}

func expectRefusal(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v want %v", err, want)
	}
}

func TestInstallWithShareScopeGrantsAndRevokesForTheOwner(t *testing.T) {
	setup := newSharingSetup(t, dbtest.CertificateOptions{})
	result, err := setup.shareWith(setup.friendGrant(access.RoleRead))
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	if result.Entry.ActorType != "install" || result.Entry.ActorID != setup.install.Principal.InstallID {
		t.Fatalf("entry actor: %+v", result.Entry)
	}
	if got := setup.f.pull(setup.friend, 0, 100); !nodeIDs(got.Nodes)[setup.root.ID] {
		t.Fatalf("friend cannot read the shared root")
	}

	entry := setup.install.RevokeEntry(t, setup.f.store, setup.root.ID, access.PrincipalTypeUser, setup.friend.UserID)
	if _, err := setup.f.store.RevokeAccessGrant(context.Background(), setup.install.Principal, setup.root.ID, entry); err != nil {
		t.Fatalf("install revoke: %v", err)
	}
	if got := setup.f.pull(setup.friend, 0, 100); nodeIDs(got.Nodes)[setup.root.ID] {
		t.Fatalf("friend still reads the root after the install revoked")
	}
}

func TestInstallShareIsRefusedWithoutTheShareScopeInTheCertificate(t *testing.T) {
	setup := newSharingSetup(t, dbtest.CertificateOptions{Scopes: []string{"calendar:read", "calendar:write"}})
	setup.install.Principal.Scopes = shareScopes
	_, err := setup.shareWith(setup.friendGrant(access.RoleRead))
	expectRefusal(t, err, database.ErrForbidden)
}

func TestInstallShareIsRefusedWithoutTheShareScopeOnTheToken(t *testing.T) {
	setup := newSharingSetup(t, dbtest.CertificateOptions{})
	setup.install.Principal.Scopes = []string{"calendar:read", "calendar:write"}
	_, err := setup.shareWith(setup.friendGrant(access.RoleRead))
	expectRefusal(t, err, database.ErrForbidden)
}

func TestInstallShareIsRefusedWithAnExpiredCertificate(t *testing.T) {
	setup := newSharingSetup(t, dbtest.CertificateOptions{ExpiresAt: time.Now().Add(-time.Hour)})
	_, err := setup.shareWith(setup.friendGrant(access.RoleRead))
	expectRefusal(t, err, database.ErrForbidden)
}

func TestInstallShareIsRefusedWhenTheUserDidNotSignTheCertificate(t *testing.T) {
	_, impostor, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	setup := newSharingSetup(t, dbtest.CertificateOptions{SignedBy: impostor})
	_, err = setup.shareWith(setup.friendGrant(access.RoleRead))
	expectRefusal(t, err, database.ErrForbidden)
}

func TestInstallShareIsRefusedOnNodesTheCertificateUserDoesNotOwn(t *testing.T) {
	setup := newSharingSetup(t, dbtest.CertificateOptions{})
	friendRoot := setup.f.createRoot(setup.friend, "calendar")
	setup.f.grant(setup.friend, friendRoot.ID, writeGrant(access.PrincipalTypeUser, setup.owner.UserID, 1))
	setup.f.grant(setup.owner, friendRoot.ID, writeGrant(access.PrincipalTypeInstall, setup.install.Principal.InstallID, 1))
	request := setup.install.GrantRequest(t, setup.f.store, friendRoot.ID, setup.friendGrant(access.RoleRead))
	_, err := setup.f.store.CreateAccessGrant(context.Background(), setup.install.Principal, friendRoot.ID, request)
	expectRefusal(t, err, database.ErrForbidden)
}

func TestInstallShareIsRefusedAboveTheInstallsOwnRole(t *testing.T) {
	setup := newSharingSetup(t, dbtest.CertificateOptions{Scopes: []string{"calendar:read", "calendar:share"}})
	setup.install.Principal.Scopes = []string{"calendar:read", "calendar:share"}
	_, err := setup.shareWith(setup.friendGrant(access.RoleWrite))
	expectRefusal(t, err, database.ErrForbidden)
}

func TestInstallShareIsRefusedAboveTheGrantedRole(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	friend := f.createUser()
	root := f.createRoot(owner, "calendar")
	install := f.accountOf(owner).NewInstall(t, f.store, dbtest.CertificateOptions{
		Scopes: shareScopes, ExpiresAt: time.Now().Add(time.Hour),
	})
	f.grant(owner, root.ID, readGrant(access.PrincipalTypeInstall, install.Principal.InstallID, 1))
	input := dbtest.ReadGrant(access.PrincipalTypeUser, friend.UserID, 1)
	input.Role = access.RoleWrite
	request := install.GrantRequest(t, f.store, root.ID, input)
	_, err := f.store.CreateAccessGrant(context.Background(), install.Principal, root.ID, request)
	expectRefusal(t, err, database.ErrForbidden)
}

func TestInstallShareIsRefusedForFacetsOutsideTheInstallsGrant(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	friend := f.createUser()
	root := f.createRoot(owner, "calendar")
	install := f.accountOf(owner).NewInstall(t, f.store, dbtest.CertificateOptions{
		Scopes: shareScopes, ExpiresAt: time.Now().Add(time.Hour),
	})
	facetGrant := writeGrant(access.PrincipalTypeInstall, install.Principal.InstallID, 1)
	facetGrant.Facets = []int{1}
	f.grant(owner, root.ID, facetGrant)

	wholeNode := dbtest.WriteGrant(access.PrincipalTypeUser, friend.UserID, 1)
	request := install.GrantRequest(t, f.store, root.ID, wholeNode)
	_, err := f.store.CreateAccessGrant(context.Background(), install.Principal, root.ID, request)
	expectRefusal(t, err, database.ErrForbidden)

	sameFacet := dbtest.WriteGrant(access.PrincipalTypeUser, friend.UserID, 1)
	sameFacet.Facets = []int{1}
	request = install.GrantRequest(t, f.store, root.ID, sameFacet)
	if _, err := f.store.CreateAccessGrant(context.Background(), install.Principal, root.ID, request); err != nil {
		t.Fatalf("a subset of the install's facets must be allowed: %v", err)
	}
}

func TestRevokedInstallCannotShare(t *testing.T) {
	setup := newSharingSetup(t, dbtest.CertificateOptions{})
	if err := setup.f.store.RevokeInstall(context.Background(), setup.owner.UserID, setup.install.Principal.InstallID); err != nil {
		t.Fatalf("revoke install: %v", err)
	}
	_, err := setup.shareWith(setup.friendGrant(access.RoleRead))
	expectRefusal(t, err, database.ErrForbidden)
}

func TestInstallCannotGrantToInstalls(t *testing.T) {
	setup := newSharingSetup(t, dbtest.CertificateOptions{})
	other := setup.f.accountOf(setup.owner).NewInstall(t, setup.f.store, dbtest.CertificateOptions{
		Scopes: shareScopes, ExpiresAt: time.Now().Add(time.Hour),
	})
	_, err := setup.shareWith(dbtest.ReadGrant(access.PrincipalTypeInstall, other.Principal.InstallID, 1))
	expectRefusal(t, err, database.ErrForbidden)
}

func TestInstallShareToAnUnknownUserIsRefused(t *testing.T) {
	setup := newSharingSetup(t, dbtest.CertificateOptions{})
	unknown := dbtest.ReadGrant(access.PrincipalTypeUser, "11111111-1111-4111-8111-111111111111", 1)
	_, err := setup.shareWith(unknown)
	expectRefusal(t, err, database.ErrUnknownPrincipal)
}

func TestInstallEntryMustNameItsOwnCertificate(t *testing.T) {
	setup := newSharingSetup(t, dbtest.CertificateOptions{})
	other := setup.f.accountOf(setup.owner).NewInstall(t, setup.f.store, dbtest.CertificateOptions{
		Scopes: shareScopes, ExpiresAt: time.Now().Add(time.Hour),
	})
	request := setup.install.GrantRequest(t, setup.f.store, setup.root.ID, setup.friendGrant(access.RoleRead))
	request.Entry.CertID = &other.CertID
	request.Entry = dbtest.SignEntry(t, setup.install.Key, request.Entry)
	_, err := setup.f.store.CreateAccessGrant(context.Background(), setup.install.Principal, setup.root.ID, request)
	expectRefusal(t, err, database.ErrForbidden)
}

func TestInstallEntryWithoutACertificateIsRefused(t *testing.T) {
	setup := newSharingSetup(t, dbtest.CertificateOptions{})
	request := setup.install.GrantRequest(t, setup.f.store, setup.root.ID, setup.friendGrant(access.RoleRead))
	request.Entry.CertID = nil
	request.Entry = dbtest.SignEntry(t, setup.install.Key, request.Entry)
	_, err := setup.f.store.CreateAccessGrant(context.Background(), setup.install.Principal, setup.root.ID, request)
	expectRefusal(t, err, database.ErrInvalidInput)
}

func TestInstallEntrySignedByAnotherKeyIsRefused(t *testing.T) {
	setup := newSharingSetup(t, dbtest.CertificateOptions{})
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := setup.install.GrantRequest(t, setup.f.store, setup.root.ID, setup.friendGrant(access.RoleRead))
	request.Entry = dbtest.SignEntry(t, stranger, request.Entry)
	_, err = setup.f.store.CreateAccessGrant(context.Background(), setup.install.Principal, setup.root.ID, request)
	expectRefusal(t, err, database.ErrInvalidInput)
}

func TestUserTokenCannotSubmitAnInstallSignedEntry(t *testing.T) {
	setup := newSharingSetup(t, dbtest.CertificateOptions{})
	request := setup.install.GrantRequest(t, setup.f.store, setup.root.ID, setup.friendGrant(access.RoleRead))
	_, err := setup.f.store.CreateAccessGrant(context.Background(), setup.owner, setup.root.ID, request)
	expectRefusal(t, err, database.ErrInvalidInput)
}

func TestRenewedCertificateAuthorisesSharing(t *testing.T) {
	setup := newSharingSetup(t, dbtest.CertificateOptions{ExpiresAt: time.Now().Add(-time.Hour)})
	renewal := newRenewalDevice(t, setup.f, setup.owner)
	renewed := renewal.renew(t, setup.f, setup.install, time.Now().Add(30*24*time.Hour))
	setup.install.CertID = renewed.CertID
	if _, err := setup.shareWith(setup.friendGrant(access.RoleRead)); err != nil {
		t.Fatalf("share with a renewed certificate: %v", err)
	}
}
