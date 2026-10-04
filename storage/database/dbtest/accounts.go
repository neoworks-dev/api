package dbtest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/accesslog"
	"github.com/neoworks/auth/storage/database"
)

var encoding = base64.RawURLEncoding

// DefaultScopes are the collection scopes test accounts act with.
var DefaultScopes = []string{
	"calendar:read", "calendar:write", "photos:read", "photos:write",
	"files:read", "files:write", "google:read", "google:write",
}

// Account is a stored user together with the identity signing key its access log
// entries are signed with.
type Account struct {
	Principal access.Principal
	Key       ed25519.PrivateKey
}

// CreateAccount stores a user whose key bundle publishes a fresh signing key.
func CreateAccount(t *testing.T, store *database.SurrealStore, scopes ...string) *Account {
	t.Helper()
	if len(scopes) == 0 {
		scopes = DefaultScopes
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	userID := uuid.NewString()
	_, err = store.CreateUserWithBundle(context.Background(), &database.CreateUserParams{
		UserID:  userID,
		Email:   userID[:8] + "@example.com",
		AuthKey: "auth-key",
		Bundle: database.KeyBundle{
			Version: 1, PwhashSalt: "salt", PwhashOps: 3, PwhashMem: 67108864,
			AmkPassword: "amkp", AmkRecovery: "amkr", IdentityPrivate: "idp",
			EncPub: "enc-" + userID, SignPub: encoding.EncodeToString(key.Public().(ed25519.PublicKey)), SelfSig: "sig",
		},
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return &Account{Principal: access.Principal{UserID: userID, Scopes: scopes}, Key: key}
}

// WriteGrant and ReadGrant build whole-node grants sealed to the given epoch.
func WriteGrant(principalType, principalID string, epoch int) database.GrantInput {
	return grant(principalType, principalID, access.RoleWrite, epoch)
}

func ReadGrant(principalType, principalID string, epoch int) database.GrantInput {
	return grant(principalType, principalID, access.RoleRead, epoch)
}

func grant(principalType, principalID, role string, epoch int) database.GrantInput {
	return database.GrantInput{
		PrincipalType: principalType, PrincipalID: principalID, Role: role,
		Epoch: epoch, WrappedKeys: encoding.EncodeToString([]byte("sealed keys")),
	}
}

// head returns the index and hash the next entry of the node's chain must carry.
func head(t *testing.T, store *database.SurrealStore, nodeID string) (int64, string) {
	t.Helper()
	current, err := store.AccessLogHead(context.Background(), nodeID)
	if err != nil {
		t.Fatalf("log head: %v", err)
	}
	if current == nil {
		return 0, accesslog.GenesisPrevHash
	}
	return current.Index + 1, current.EntryHash
}

// GrantRequest builds a signed grant request extending the node's current chain.
func (account *Account) GrantRequest(t *testing.T, store *database.SurrealStore, nodeID string, input database.GrantInput) database.GrantRequest {
	t.Helper()
	index, prevHash := head(t, store, nodeID)
	return account.GrantRequestAt(t, nodeID, input, index, prevHash)
}

// GrantRequestAt builds a signed grant request for an explicit chain position.
func (account *Account) GrantRequestAt(t *testing.T, nodeID string, input database.GrantInput, index int64, prevHash string) database.GrantRequest {
	t.Helper()
	keysHash, err := accesslog.WrappedKeysHash(input.WrappedKeys)
	if err != nil {
		t.Fatalf("keys hash: %v", err)
	}
	entry := accesslog.Entry{
		NodeID: nodeID, Index: index, PrevHash: prevHash, Action: accesslog.ActionGrant,
		PrincipalType: input.PrincipalType, PrincipalID: input.PrincipalID, Role: input.Role,
		Facets: input.Facets, Epoch: input.Epoch, WrappedKeysHash: keysHash,
		ActorType: "user", ActorID: account.Principal.UserID,
	}
	return database.GrantRequest{Grant: input, Entry: account.sign(t, entry)}
}

// RevokeEntry builds a signed revoke entry extending the node's current chain.
func (account *Account) RevokeEntry(t *testing.T, store *database.SurrealStore, nodeID, principalType, principalID string) accesslog.Entry {
	t.Helper()
	index, prevHash := head(t, store, nodeID)
	entry := accesslog.Entry{
		NodeID: nodeID, Index: index, PrevHash: prevHash, Action: accesslog.ActionRevoke,
		PrincipalType: principalType, PrincipalID: principalID, Role: access.RoleRead, Epoch: 1,
		ActorType: "user", ActorID: account.Principal.UserID,
	}
	return account.sign(t, entry)
}

func (account *Account) sign(t *testing.T, entry accesslog.Entry) accesslog.Entry {
	t.Helper()
	entryBytes, err := entry.Bytes()
	if err != nil {
		t.Fatalf("entry bytes: %v", err)
	}
	entry.Signature = encoding.EncodeToString(ed25519.Sign(account.Key, entryBytes))
	return entry
}

// Grant signs and stores a grant, failing the test on any error.
func (account *Account) Grant(t *testing.T, store *database.SurrealStore, nodeID string, input database.GrantInput) *database.GrantResult {
	t.Helper()
	result, err := store.CreateAccessGrant(context.Background(), account.Principal, nodeID, account.GrantRequest(t, store, nodeID, input))
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	return result
}

// Revoke signs and stores a revoke entry, failing the test on any error.
func (account *Account) Revoke(t *testing.T, store *database.SurrealStore, nodeID, principalType, principalID string) {
	t.Helper()
	entry := account.RevokeEntry(t, store, nodeID, principalType, principalID)
	if _, err := store.RevokeAccessGrant(context.Background(), account.Principal, nodeID, entry); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}
