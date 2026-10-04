package accesslog

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

const (
	delegationContext = "nw-delegation-v1"
	renewalContext    = "nw-renewal-v1"
)

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
	// OriginCertID and RenewalCertID are set on a renewed certificate, which the
	// authenticator's renewal key signs instead of the user's identity key.
	OriginCertID  string `json:"originCertId,omitempty"`
	RenewalCertID string `json:"renewalCertId,omitempty"`
}

// RenewalCertificate lets one authenticator device extend delegation
// certificates; the user's identity key signs it once at enrollment.
type RenewalCertificate struct {
	Version        int       `json:"v"`
	RenewalCertID  string    `json:"renewalCertId"`
	UserID         string    `json:"userId"`
	DeviceID       string    `json:"deviceId"`
	RenewalSignPub string    `json:"renewalSignPub"`
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
	raw, err := verifySignedBytes(delegationContext, certBytes, certSignature, userSignPub)
	if err != nil {
		return nil, err
	}
	return parseCertificate(raw, now)
}

// VerifyIdentityCertificate verifies a certificate the user's identity key
// signed and refuses one that claims to be a renewal.
func VerifyIdentityCertificate(certBytes, certSignature, userSignPub string, now time.Time) (*Certificate, error) {
	certificate, err := VerifyCertificate(certBytes, certSignature, userSignPub, now)
	if err != nil {
		return nil, err
	}
	if certificate.RenewalCertID != "" || certificate.OriginCertID != "" {
		return nil, errors.New("certificate is a renewal, not an identity-signed origin")
	}
	return certificate, nil
}

// PeekRenewalLinks reads the renewal links of a certificate without verifying
// it, only to decide which certificates to load before verifying.
func PeekRenewalLinks(certBytes string) (originCertID, renewalCertID string, err error) {
	raw, err := encoding.DecodeString(certBytes)
	if err != nil {
		return "", "", errors.New("certificate is not base64url")
	}
	var links Certificate
	if err := json.Unmarshal(raw, &links); err != nil {
		return "", "", errors.New("certificate is not valid JSON")
	}
	return links.OriginCertID, links.RenewalCertID, nil
}

// VerifyRenewalCertificate checks a renewal certificate against the user's
// identity signing key and rejects an expired one.
func VerifyRenewalCertificate(renewalBytes, renewalSignature, userSignPub string, now time.Time) (*RenewalCertificate, error) {
	raw, err := verifySignedBytes(renewalContext, renewalBytes, renewalSignature, userSignPub)
	if err != nil {
		return nil, err
	}
	var renewal RenewalCertificate
	if err := json.Unmarshal(raw, &renewal); err != nil {
		return nil, errors.New("renewal certificate is not valid JSON")
	}
	if renewal.Version != 1 {
		return nil, errors.New("unsupported renewal certificate version")
	}
	if !now.Before(renewal.ExpiresAt) {
		return nil, errors.New("renewal certificate has expired")
	}
	return &renewal, nil
}

// VerifyRenewedCertificate checks a certificate signed by a renewal key: the
// signature verifies under the renewal certificate's key, the identity-signed
// origin matches it field by field, its scopes are a subset of the origin's and
// it does not outlive the renewal certificate.
func VerifyRenewedCertificate(certBytes, certSignature string, renewal *RenewalCertificate, origin *Certificate, now time.Time) (*Certificate, error) {
	raw, err := verifySignedBytes(delegationContext, certBytes, certSignature, renewal.RenewalSignPub)
	if err != nil {
		return nil, err
	}
	renewed, err := parseCertificate(raw, now)
	if err != nil {
		return nil, err
	}
	if err := checkRenewalLinks(renewed, renewal, origin); err != nil {
		return nil, err
	}
	return renewed, nil
}

func checkRenewalLinks(renewed *Certificate, renewal *RenewalCertificate, origin *Certificate) error {
	if renewed.RenewalCertID != renewal.RenewalCertID || renewed.OriginCertID != origin.CertID {
		return errors.New("certificate does not reference this renewal and origin")
	}
	if renewed.UserID != renewal.UserID {
		return errors.New("renewal certificate belongs to another user")
	}
	sameIdentity := renewed.UserID == origin.UserID && renewed.InstallID == origin.InstallID &&
		renewed.ClientID == origin.ClientID && renewed.InstallEncPub == origin.InstallEncPub &&
		renewed.InstallSignPub == origin.InstallSignPub
	if !sameIdentity {
		return errors.New("renewed certificate differs from its origin")
	}
	for _, scope := range renewed.Scopes {
		if !origin.HasScope(scope) {
			return errors.New("renewed certificate widens the origin's scopes")
		}
	}
	if renewed.ExpiresAt.After(renewal.ExpiresAt) {
		return errors.New("renewed certificate outlives the renewal certificate")
	}
	return nil
}

func verifySignedBytes(context, signedBytes, signature, signPub string) ([]byte, error) {
	publicKey, err := encoding.DecodeString(signPub)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("signer has no usable signing key")
	}
	raw, err := encoding.DecodeString(signedBytes)
	if err != nil {
		return nil, errors.New("signed bytes are not base64url")
	}
	decodedSignature, err := encoding.DecodeString(signature)
	if err != nil {
		return nil, errors.New("signature is not base64url")
	}
	if !ed25519.Verify(publicKey, tlv(context, raw), decodedSignature) {
		return nil, errors.New("signature does not verify")
	}
	return raw, nil
}

// VerifyOriginCertificate verifies an identity-signed certificate that renewed
// ones extend. Its own expiry is not checked: renewals outlive it.
func VerifyOriginCertificate(certBytes, certSignature, userSignPub string) (*Certificate, error) {
	raw, err := verifySignedBytes(delegationContext, certBytes, certSignature, userSignPub)
	if err != nil {
		return nil, err
	}
	origin, err := parseCertificate(raw, time.Time{})
	if err != nil {
		return nil, err
	}
	if origin.RenewalCertID != "" || origin.OriginCertID != "" {
		return nil, errors.New("origin certificate is itself a renewal")
	}
	return origin, nil
}

// PeekExpiry reads a certificate's expiry and origin link without verifying it;
// only for listing certificates that are about to expire.
func PeekExpiry(certBytes string) (time.Time, string, error) {
	raw, err := encoding.DecodeString(certBytes)
	if err != nil {
		return time.Time{}, "", errors.New("certificate is not base64url")
	}
	var peeked Certificate
	if err := json.Unmarshal(raw, &peeked); err != nil {
		return time.Time{}, "", errors.New("certificate is not valid JSON")
	}
	return peeked.ExpiresAt, peeked.OriginCertID, nil
}

func parseCertificate(raw []byte, now time.Time) (*Certificate, error) {
	var certificate Certificate
	if err := json.Unmarshal(raw, &certificate); err != nil {
		return nil, errors.New("certificate is not valid JSON")
	}
	if certificate.Version != 1 {
		return nil, errors.New("unsupported certificate version")
	}
	if !now.IsZero() && !now.Before(certificate.ExpiresAt) {
		return nil, errors.New("certificate has expired")
	}
	return &certificate, nil
}
