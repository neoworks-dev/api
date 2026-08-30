package database

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
)

// Encryptor seals secrets (per-instance root passwords) at rest with AES-256-GCM.
// The key comes from INSTANCE_SECRET_KEY. When no key is configured the store
// keeps a nil Encryptor and stores secrets verbatim — acceptable only for local
// development against the shared root/root instance.
type Encryptor struct {
	aead cipher.AEAD
}

// NewEncryptor builds an Encryptor from a base64-encoded 32-byte key.
func NewEncryptor(keyBase64 string) (*Encryptor, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes (got %d)", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	return &Encryptor{aead: aead}, nil
}

// Seal returns base64(nonce || ciphertext).
func (e *Encryptor) Seal(plain string) (string, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	sealed := e.aead.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// sealWith is Seal for an optional Encryptor: a nil one stores the plaintext
// verbatim, and a failure to seal is logged rather than fatal, so a
// misconfigured key never blocks a write path.
func sealWith(e *Encryptor, plain string) string {
	if e == nil {
		return plain
	}
	sealed, err := e.Seal(plain)
	if err != nil {
		slog.Error("seal secret", "error", err)
		return plain
	}
	return sealed
}

// openWith reverses sealWith. A value that does not open is returned as-is —
// rows written before a key was configured are stored verbatim.
func openWith(e *Encryptor, stored string) string {
	if e == nil {
		return stored
	}
	plain, err := e.Open(stored)
	if err != nil {
		return stored
	}
	return plain
}

// Open reverses Seal.
func (e *Encryptor) Open(sealed string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	nonceSize := e.aead.NonceSize()
	if len(raw) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plain, err := e.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("open: %w", err)
	}
	return string(plain), nil
}
