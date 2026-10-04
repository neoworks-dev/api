package accesslog

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

const delegationContext = "nw-delegation-v1"

// Certificate is the user's delegation of an install. It is parsed only after
// its signature has been verified.
type Certificate struct {
	Version        int       `json:"v"`
	CertID         string    `json:"certId"`
	UserID         string    `json:"userId"`
	InstallID      string    `json:"installId"`
	ClientID       string    `json:"clientId"`
	InstallEncPub  string    `json:"installEncPub"`
	InstallSignPub string    `json:"installSignPub"`
	Scopes         []string  `json:"scopes"`
	IssuedAt       time.Time `json:"issuedAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

// HasScope reports whether the certificate lists the scope.
func (certificate *Certificate) HasScope(scope string) bool {
	return slices.Contains(certificate.Scopes, scope)
}

// VerifyCertificate checks the certificate's signature against the user's
// identity signing key (all values base64url), parses it and rejects an expired one.
func VerifyCertificate(certBytes, certSignature, userSignPub string, now time.Time) (*Certificate, error) {
	publicKey, err := encoding.DecodeString(userSignPub)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("the user has no usable signing key")
	}
	raw, err := encoding.DecodeString(certBytes)
	if err != nil {
		return nil, errors.New("certificate is not base64url")
	}
	signature, err := encoding.DecodeString(certSignature)
	if err != nil {
		return nil, errors.New("certificate signature is not base64url")
	}
	if !ed25519.Verify(publicKey, tlv(delegationContext, raw), signature) {
		return nil, errors.New("certificate signature does not verify")
	}
	return parseCertificate(raw, now)
}

func parseCertificate(raw []byte, now time.Time) (*Certificate, error) {
	var certificate Certificate
	if err := json.Unmarshal(raw, &certificate); err != nil {
		return nil, errors.New("certificate is not valid JSON")
	}
	if certificate.Version != 1 {
		return nil, errors.New("unsupported certificate version")
	}
	if !now.Before(certificate.ExpiresAt) {
		return nil, errors.New("certificate has expired")
	}
	return &certificate, nil
}
