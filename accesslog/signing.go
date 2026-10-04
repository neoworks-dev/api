package accesslog

import "crypto/ed25519"

// SignDelegation signs delegation certificate bytes the way the account vault
// (identity key) or an authenticator (renewal key) does. Used by tests and tools.
func SignDelegation(key ed25519.PrivateKey, certBytes []byte) string {
	return encoding.EncodeToString(ed25519.Sign(key, tlv(delegationContext, certBytes)))
}

// SignRenewal signs renewal certificate bytes with the user's identity key.
func SignRenewal(key ed25519.PrivateKey, renewalBytes []byte) string {
	return encoding.EncodeToString(ed25519.Sign(key, tlv(renewalContext, renewalBytes)))
}

// Encode returns the base64url form used for certificate bytes on the wire.
func Encode(raw []byte) string {
	return encoding.EncodeToString(raw)
}
