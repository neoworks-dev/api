package database

import (
	"encoding/base64"
	"testing"
)

func testKey() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 32))
}

func TestEncryptorRoundTrip(t *testing.T) {
	enc, err := NewEncryptor(testKey())
	if err != nil {
		t.Fatalf("new encryptor: %v", err)
	}
	sealed, err := enc.Seal("hunter2")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if sealed == "hunter2" {
		t.Fatal("secret was not sealed")
	}
	got, err := enc.Open(sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got != "hunter2" {
		t.Fatalf("open = %q, want %q", got, "hunter2")
	}
}

func TestEncryptorRejectsShortKey(t *testing.T) {
	if _, err := NewEncryptor(base64.StdEncoding.EncodeToString(make([]byte, 16))); err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}

func TestSealOpenNilEncryptorPassthrough(t *testing.T) {
	s := &SurrealStore{}
	if got := s.sealSecret("plain"); got != "plain" {
		t.Fatalf("sealSecret with nil encryptor = %q, want passthrough", got)
	}
	if got := s.openSecret("plain"); got != "plain" {
		t.Fatalf("openSecret with nil encryptor = %q, want passthrough", got)
	}
}
