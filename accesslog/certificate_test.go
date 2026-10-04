package accesslog_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neoworks/auth/accesslog"
)

func loadDelegationVector(t *testing.T) (certBytes, signature, signPub string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "libneoworks", "test-vectors", "v1.json"))
	if err != nil {
		t.Skip("shared test vectors not available")
	}
	var vectors struct {
		Delegation struct {
			CertBytesHex string `json:"certBytesHex"`
			CertSigHex   string `json:"certSigHex"`
			UserSignPub  string `json:"userSignPubHex"`
		} `json:"delegation"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	encode := func(value string) string {
		decoded, _ := hex.DecodeString(value)
		return b64.EncodeToString(decoded)
	}
	delegation := vectors.Delegation
	return encode(delegation.CertBytesHex), encode(delegation.CertSigHex), encode(delegation.UserSignPub)
}

func TestSharedDelegationVectorVerifies(t *testing.T) {
	certBytes, signature, signPub := loadDelegationVector(t)
	valid := time.Unix(1790000000, 0)
	certificate, err := accesslog.VerifyCertificate(certBytes, signature, signPub, valid)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if certificate.UserID != "11111111-1111-4111-8111-111111111111" || !certificate.HasScope("calendar:write") {
		t.Fatalf("parsed certificate: %+v", certificate)
	}
}

func TestCertificateIsRefusedWhenExpiredOrForged(t *testing.T) {
	certBytes, signature, signPub := loadDelegationVector(t)
	if _, err := accesslog.VerifyCertificate(certBytes, signature, signPub, time.Unix(1793600000, 0)); err == nil {
		t.Error("an expired certificate must be refused")
	}
	_, otherPub := signedEntry(t, make([]byte, 32))
	if _, err := accesslog.VerifyCertificate(certBytes, signature, otherPub, time.Unix(1790000000, 0)); err == nil {
		t.Error("a certificate not signed by the user's key must be refused")
	}
	tampered := b64.EncodeToString([]byte(`{"v":1,"userId":"x","expiresAt":"2099-01-01T00:00:00Z"}`))
	if _, err := accesslog.VerifyCertificate(tampered, signature, signPub, time.Unix(1790000000, 0)); err == nil {
		t.Error("tampered certificate bytes must be refused")
	}
}
