package shared

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
