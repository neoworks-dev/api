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
	t        *testing.T
	store    *database.SurrealStore
	accounts map[string]*dbtest.Account
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return &fixture{t: t, store: dbtest.New(t), accounts: map[string]*dbtest.Account{}}
}

func (f *fixture) createUser() access.Principal {
	f.t.Helper()
	account := dbtest.CreateAccount(f.t, f.store)
	f.accounts[account.Principal.UserID] = account
	return account.Principal
}

// accountOf returns the signing account behind a user principal.
func (f *fixture) accountOf(principal access.Principal) *dbtest.Account {
	f.t.Helper()
	account, found := f.accounts[principal.UserID]
	if !found {
		f.t.Fatalf("no account for %s", principal.UserID)
	}
	return account
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
