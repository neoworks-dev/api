package dbtest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/accesslog"
	"github.com/neoworks/auth/storage/database"
)

// Install is a stored install with the signing key its entries are signed with
// and the identity-signed delegation certificate that authorises it.
type Install struct {
	Principal access.Principal
	Key       ed25519.PrivateKey
	CertID    string
}

// CertificateOptions shape the delegation certificate a test install gets.
type CertificateOptions struct {
	Scopes    []string
	ExpiresAt time.Time
	// SignedBy replaces the key that signs the certificate; nil means the user.
	SignedBy ed25519.PrivateKey
}

// NewInstall registers an install for the account and stores a delegation
// certificate listing the scopes. The install's token carries the same scopes.
func (account *Account) NewInstall(t *testing.T, store *database.SurrealStore, options CertificateOptions) *Install {
	t.Helper()
	publicKey, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate install key: %v", err)
	}
	installID, certID := uuid.NewString(), uuid.NewString()
	installSignPub := encoding.EncodeToString(publicKey)
	if _, err := store.CreateInstall(context.Background(), database.CreateInstallParams{
		InstallID: installID, UserID: account.Principal.UserID, ClientID: "neoworks-calendar",
		EncPub: "enc", SignPub: installSignPub, Name: "test install",
	}); err != nil {
		t.Fatalf("create install: %v", err)
	}
	certificate := accesslog.Certificate{
		Version: 1, CertID: certID, UserID: account.Principal.UserID, InstallID: installID,
		ClientID: "neoworks-calendar", InstallEncPub: "enc", InstallSignPub: installSignPub,
		Scopes: options.Scopes, IssuedAt: time.Now(), ExpiresAt: options.ExpiresAt,
	}
	signer := options.SignedBy
	if signer == nil {
		signer = account.Key
	}
	StoreCertificate(t, store, certificate, signer)
	return &Install{
		Principal: access.Principal{UserID: account.Principal.UserID, InstallID: installID, Scopes: options.Scopes},
		Key:       key, CertID: certID,
	}
}

// StoreCertificate signs the certificate with the key and stores it.
func StoreCertificate(t *testing.T, store *database.SurrealStore, certificate accesslog.Certificate, signer ed25519.PrivateKey) {
	t.Helper()
	raw, err := json.Marshal(certificate)
	if err != nil {
		t.Fatalf("marshal certificate: %v", err)
	}
	params := database.CreateCertificateParams{
		CertID: certificate.CertID, UserID: certificate.UserID, InstallID: certificate.InstallID,
		Bytes: accesslog.Encode(raw), Signature: accesslog.SignDelegation(signer, raw),
	}
	if _, err := store.CreateCertificate(context.Background(), params); err != nil {
		t.Fatalf("store certificate: %v", err)
	}
}

// GrantRequest builds a grant request signed by the install, extending the
// node's current chain.
func (install *Install) GrantRequest(t *testing.T, store *database.SurrealStore, nodeID string, input database.GrantInput) database.GrantRequest {
	t.Helper()
	index, prevHash := head(t, store, nodeID)
	keysHash, err := accesslog.WrappedKeysHash(input.WrappedKeys)
	if err != nil {
		t.Fatalf("keys hash: %v", err)
	}
	entry := accesslog.Entry{
		NodeID: nodeID, Index: index, PrevHash: prevHash, Action: accesslog.ActionGrant,
		PrincipalType: input.PrincipalType, PrincipalID: input.PrincipalID, Role: input.Role,
		Facets: input.Facets, Epoch: input.Epoch, WrappedKeysHash: keysHash,
		ActorType: "install", ActorID: install.Principal.InstallID, CertID: &install.CertID,
	}
	return database.GrantRequest{Grant: input, Entry: SignEntry(t, install.Key, entry)}
}

// RevokeEntry builds a revoke entry signed by the install.
func (install *Install) RevokeEntry(t *testing.T, store *database.SurrealStore, nodeID, principalType, principalID string) accesslog.Entry {
	t.Helper()
	index, prevHash := head(t, store, nodeID)
	entry := accesslog.Entry{
		NodeID: nodeID, Index: index, PrevHash: prevHash, Action: accesslog.ActionRevoke,
		PrincipalType: principalType, PrincipalID: principalID,
		ActorType: "install", ActorID: install.Principal.InstallID, CertID: &install.CertID,
	}
	return SignEntry(t, install.Key, entry)
}

// SignEntry signs an entry with the key.
func SignEntry(t *testing.T, key ed25519.PrivateKey, entry accesslog.Entry) accesslog.Entry {
	t.Helper()
	entryBytes, err := entry.Bytes()
	if err != nil {
		t.Fatalf("entry bytes: %v", err)
	}
	entry.Signature = encoding.EncodeToString(ed25519.Sign(key, entryBytes))
	return entry
}
