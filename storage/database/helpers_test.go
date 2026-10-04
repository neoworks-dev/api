package database_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
)

type fixture struct {
	t     *testing.T
	store *database.SurrealStore
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return &fixture{t: t, store: dbtest.New(t)}
}

func (f *fixture) createUser() access.Principal {
	f.t.Helper()
	userID := uuid.NewString()
	_, err := f.store.CreateUserWithBundle(context.Background(), &database.CreateUserParams{
		UserID:  userID,
		Email:   userID[:8] + "@example.com",
		AuthKey: "auth-key",
		Bundle: database.KeyBundle{
			Version: 1, PwhashSalt: "salt", PwhashOps: 3, PwhashMem: 67108864,
			AmkPassword: "amkp", AmkRecovery: "amkr", IdentityPrivate: "idp",
			EncPub: "enc-" + userID, SignPub: "sign-" + userID, SelfSig: "sig",
		},
	})
	if err != nil {
		f.t.Fatalf("create user: %v", err)
	}
	return userPrincipal(userID, "calendar:read", "calendar:write", "photos:read", "photos:write", "files:read", "files:write")
}

func userPrincipal(userID string, scopes ...string) access.Principal {
	return access.Principal{UserID: userID, Scopes: scopes}
}

func installPrincipal(userID, installID string, scopes ...string) access.Principal {
	return access.Principal{UserID: userID, InstallID: installID, Scopes: scopes}
}

// createInstall registers an install and a delegation certificate for it.
func (f *fixture) createInstall(owner access.Principal, scopes ...string) (access.Principal, string) {
	f.t.Helper()
	ctx := context.Background()
	installID := uuid.NewString()
	certID := uuid.NewString()
	if _, err := f.store.CreateInstall(ctx, database.CreateInstallParams{
		InstallID: installID, UserID: owner.UserID, ClientID: "neoworks-calendar",
		EncPub: "enc", SignPub: "sign", Name: "test install",
	}); err != nil {
		f.t.Fatalf("create install: %v", err)
	}
	if _, err := f.store.CreateCertificate(ctx, database.CreateCertificateParams{
		CertID: certID, UserID: owner.UserID, InstallID: installID, Bytes: "cert", Signature: "certsig",
	}); err != nil {
		f.t.Fatalf("create certificate: %v", err)
	}
	return installPrincipal(owner.UserID, installID, scopes...), certID
}
