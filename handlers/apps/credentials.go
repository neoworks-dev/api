package apps

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	clientIDPrefix     = "app_"
	clientIDBytes      = 10
	clientSecretPrefix = "nws_"
	clientSecretBytes  = 24
)

func randomHex(prefix string, byteCount int) (string, error) {
	random := make([]byte, byteCount)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("random credential: %w", err)
	}
	return prefix + hex.EncodeToString(random), nil
}

func newClientID() (string, error) {
	return randomHex(clientIDPrefix, clientIDBytes)
}

// newClientSecret returns a secret and the bcrypt hash apps/oauth verifies
// client.secret_hash against.
func newClientSecret() (secret string, secretHash string, err error) {
	secret, err = randomHex(clientSecretPrefix, clientSecretBytes)
	if err != nil {
		return "", "", err
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("hash client secret: %w", err)
	}
	return secret, string(hashed), nil
}
