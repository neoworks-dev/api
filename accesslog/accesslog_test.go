package accesslog_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/neoworks/auth/accesslog"
)

var b64 = base64.RawURLEncoding

func signedEntry(t *testing.T, seed []byte) (accesslog.Entry, string) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(seed)
	keysHash, err := accesslog.WrappedKeysHash(b64.EncodeToString([]byte("sealed keys")))
	if err != nil {
		t.Fatal(err)
	}
	entry := accesslog.Entry{
		NodeID: "11111111-1111-4111-8111-111111111111", Index: 0, PrevHash: accesslog.GenesisPrevHash,
		Action: accesslog.ActionGrant, PrincipalType: "user", PrincipalID: "22222222-2222-4222-8222-222222222222",
		Role: "write", Facets: []int{0, 2}, Epoch: 1, WrappedKeysHash: keysHash,
		ActorType: "user", ActorID: "22222222-2222-4222-8222-222222222222",
	}
	entryBytes, err := entry.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	entry.Signature = b64.EncodeToString(ed25519.Sign(private, entryBytes))
	return entry, b64.EncodeToString(private.Public().(ed25519.PublicKey))
}

func TestSignedEntryVerifiesAndTamperingDoesNot(t *testing.T) {
	entry, signPub := signedEntry(t, make([]byte, 32))
	if err := entry.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := entry.VerifySignature(signPub); err != nil {
		t.Fatalf("verify: %v", err)
	}
	tampered := entry
	tampered.Role = "read"
	if err := tampered.VerifySignature(signPub); err == nil {
		t.Fatal("a changed role must break the signature")
	}
	_, otherPub := signedEntry(t, []byte("0123456789abcdef0123456789abcdef"))
	if err := entry.VerifySignature(otherPub); err == nil {
		t.Fatal("another key must not verify")
	}
}

func TestEntryHashCoversTheSignedBytes(t *testing.T) {
	first, _ := signedEntry(t, make([]byte, 32))
	again, _ := signedEntry(t, make([]byte, 32))
	hashA, _ := first.ComputedHash()
	hashB, _ := again.ComputedHash()
	if hashA != hashB {
		t.Fatal("hash must be deterministic")
	}
	again.Index = 1
	hashC, _ := again.ComputedHash()
	if hashA == hashC {
		t.Fatal("hash must cover the index")
	}
}

func TestValidateRejectsMalformedEntries(t *testing.T) {
	good, _ := signedEntry(t, make([]byte, 32))
	cert := "c"
	cases := map[string]func(*accesslog.Entry){
		"short prevHash":         func(e *accesslog.Entry) { e.PrevHash = "AAAA" },
		"short signature":        func(e *accesslog.Entry) { e.Signature = "AAAA" },
		"install actor no cert":  func(e *accesslog.Entry) { e.ActorType = "install" },
		"user actor with cert":   func(e *accesslog.Entry) { e.CertID = &cert },
		"install grant no cert":  func(e *accesslog.Entry) { e.PrincipalType = "install" },
		"unknown actor type":     func(e *accesslog.Entry) { e.ActorType = "device" },
		"unknown action":         func(e *accesslog.Entry) { e.Action = "share" },
		"grant without keysHash": func(e *accesslog.Entry) { e.WrappedKeysHash = "" },
		"revoke with keysHash":   func(e *accesslog.Entry) { e.Action = accesslog.ActionRevoke },
		"revoke with role":       func(e *accesslog.Entry) { e.Action, e.WrappedKeysHash, e.Epoch = accesslog.ActionRevoke, "", 0 },
		"negative index":         func(e *accesslog.Entry) { e.Index = -1 },
	}
	for name, mutate := range cases {
		entry := good
		mutate(&entry)
		if err := entry.Validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	installEntry := good
	installEntry.ActorType, installEntry.CertID = "install", &cert
	if err := installEntry.Validate(); err != nil {
		t.Errorf("an install entry with a certId is valid: %v", err)
	}
	installGrant := good
	installGrant.PrincipalType, installGrant.CertID = "install", &cert
	if err := installGrant.Validate(); err != nil {
		t.Errorf("a user grant to an install naming its certId is valid: %v", err)
	}
	revoke := good
	revoke.Action, revoke.WrappedKeysHash, revoke.Role, revoke.Epoch, revoke.Facets = accesslog.ActionRevoke, "", "", 0, nil
	if err := revoke.Validate(); err != nil {
		t.Errorf("a revoke with an empty hash is valid: %v", err)
	}
}

// The shared vectors pin the tlv encoding the entry bytes are built on.
func TestEntryBytesUseTheSharedTlvEncoding(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "libneoworks", "test-vectors", "v1.json"))
	if err != nil {
		t.Skip("shared test vectors not available")
	}
	var vectors struct {
		Hash []struct {
			Input    string `json:"inputUtf8"`
			Expected string `json:"expectedHex"`
		} `json:"hash"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	empty, _ := accesslog.WrappedKeysHash("")
	want, _ := hex.DecodeString(vectors.Hash[0].Expected)
	if empty != b64.EncodeToString(want) {
		t.Fatalf("H(empty) %s does not match the shared vector", empty)
	}
	entry, _ := signedEntry(t, make([]byte, 32))
	entryBytes, _ := entry.Bytes()
	if string(entryBytes[:19]) != "nw-access-entry-v1\x00" {
		t.Fatalf("entry bytes must start with the context and a zero byte: %q", entryBytes[:19])
	}
}
