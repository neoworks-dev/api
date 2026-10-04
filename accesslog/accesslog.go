// Package accesslog defines the hash-chained access log: the entry format, its
// signed bytes and its hash. Entries are produced and signed by clients; the
// server verifies and stores them.
package accesslog

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/blake2b"
)

const (
	ActionGrant  = "grant"
	ActionRevoke = "revoke"

	entryContext = "nw-access-entry-v1"
	hashBytes    = 32
)

var encoding = base64.RawURLEncoding

// GenesisPrevHash is the prevHash of entry 0: 32 zero bytes, base64url.
var GenesisPrevHash = encoding.EncodeToString(make([]byte, hashBytes))

// Entry is one link of a node's access chain. Binary values are base64url.
type Entry struct {
	NodeID          string  `json:"nodeId"`
	Index           int64   `json:"index"`
	PrevHash        string  `json:"prevHash"`
	Action          string  `json:"action"`
	PrincipalType   string  `json:"principalType"`
	PrincipalID     string  `json:"principalId"`
	Role            string  `json:"role"`
	Facets          []int   `json:"facets"`
	Epoch           int     `json:"epoch"`
	WrappedKeysHash string  `json:"wrappedKeysHash"`
	ActorType       string  `json:"actorType"`
	ActorID         string  `json:"actorId"`
	CertID          *string `json:"certId"`
	Signature       string  `json:"signature"`
	EntryHash       string  `json:"entryHash,omitempty"`
}

// Hash returns H(wrappedKeys) as base64url for a grant's wrappedKeys value
// (itself base64url), which is what an entry's wrappedKeysHash must equal.
func WrappedKeysHash(wrappedKeys string) (string, error) {
	raw, err := encoding.DecodeString(wrappedKeys)
	if err != nil {
		return "", errors.New("wrappedKeys is not base64url")
	}
	sum := blake2b.Sum256(raw)
	return encoding.EncodeToString(sum[:]), nil
}

// Validate checks the entry's shape: the sizes of its binary fields, its action
// and that a revoke carries no wrapped-keys hash.
func (entry Entry) Validate() error {
	if entry.Index < 0 {
		return errors.New("index must not be negative")
	}
	if err := requireSize("prevHash", entry.PrevHash, hashBytes); err != nil {
		return err
	}
	if err := requireSize("signature", entry.Signature, ed25519.SignatureSize); err != nil {
		return err
	}
	if err := entry.validateActor(); err != nil {
		return err
	}
	return entry.validateAction()
}

// validateActor pins certId: an install actor names its own certificate, a user
// granting to an install names that install's certificate (it proves the install
// is the user's), and any other user entry carries none.
func (entry Entry) validateActor() error {
	hasCertificate := entry.CertID != nil && *entry.CertID != ""
	switch {
	case entry.ActorType == "install":
		return requireCertificate(hasCertificate, "an install signs with its certId")
	case entry.ActorType != "user":
		return fmt.Errorf("unknown actorType %q", entry.ActorType)
	case entry.Action == ActionGrant && entry.PrincipalType == "install":
		return requireCertificate(hasCertificate, "a grant to an install names the install's certId")
	case entry.CertID != nil:
		return errors.New("only grants to an install carry a user-signed certId")
	default:
		return nil
	}
}

func requireCertificate(hasCertificate bool, message string) error {
	if !hasCertificate {
		return errors.New(message)
	}
	return nil
}

func (entry Entry) validateAction() error {
	switch entry.Action {
	case ActionGrant:
		return requireSize("wrappedKeysHash", entry.WrappedKeysHash, hashBytes)
	case ActionRevoke:
		canonical := entry.WrappedKeysHash == "" && entry.Role == "" && entry.Facets == nil && entry.Epoch == 0
		if !canonical {
			return errors.New("a revoke carries no role, facets, epoch or wrappedKeysHash")
		}
		return nil
	default:
		return fmt.Errorf("unknown action %q", entry.Action)
	}
}

func requireSize(name, value string, size int) error {
	raw, err := encoding.DecodeString(value)
	if err != nil || len(raw) != size {
		return fmt.Errorf("%s must be %d bytes of base64url", name, size)
	}
	return nil
}

// Bytes returns the bytes the actor signs and that the entry hash covers.
func (entry Entry) Bytes() ([]byte, error) {
	prevHash, err := encoding.DecodeString(entry.PrevHash)
	if err != nil {
		return nil, errors.New("prevHash is not base64url")
	}
	keysHash, err := encoding.DecodeString(entry.WrappedKeysHash)
	if err != nil {
		return nil, errors.New("wrappedKeysHash is not base64url")
	}
	certID := ""
	if entry.CertID != nil {
		certID = *entry.CertID
	}
	return tlv(entryContext,
		[]byte(entry.NodeID), u64(uint64(entry.Index)), prevHash, []byte(entry.Action),
		[]byte(entry.PrincipalType), []byte(entry.PrincipalID), []byte(entry.Role),
		[]byte(facetsCSV(entry.Facets)), u32(uint32(entry.Epoch)), keysHash,
		[]byte(entry.ActorType), []byte(entry.ActorID), []byte(certID)), nil
}

// ComputedHash returns H(entryBytes) as base64url.
func (entry Entry) ComputedHash() (string, error) {
	entryBytes, err := entry.Bytes()
	if err != nil {
		return "", err
	}
	sum := blake2b.Sum256(entryBytes)
	return encoding.EncodeToString(sum[:]), nil
}

// VerifySignature checks the entry's Ed25519 signature against the actor's
// signing public key (base64url): the user's identity key, or the install's key.
func (entry Entry) VerifySignature(signPub string) error {
	publicKey, err := encoding.DecodeString(signPub)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("actor has no usable signing key")
	}
	signature, err := encoding.DecodeString(entry.Signature)
	if err != nil {
		return errors.New("signature is not base64url")
	}
	entryBytes, err := entry.Bytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, entryBytes, signature) {
		return errors.New("signature does not verify")
	}
	return nil
}

func facetsCSV(facets []int) string {
	parts := make([]string, 0, len(facets))
	for _, facet := range facets {
		parts = append(parts, strconv.Itoa(facet))
	}
	return strings.Join(parts, ",")
}

func u32(value uint32) []byte {
	encoded := make([]byte, 4)
	binary.BigEndian.PutUint32(encoded, value)
	return encoded
}

func u64(value uint64) []byte {
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, value)
	return encoded
}

// tlv is utf8(context) ‖ 0x00 ‖ for each field u32be(len) ‖ bytes.
func tlv(context string, fields ...[]byte) []byte {
	encoded := append([]byte(context), 0)
	for _, field := range fields {
		encoded = append(encoded, u32(uint32(len(field)))...)
		encoded = append(encoded, field...)
	}
	return encoded
}
