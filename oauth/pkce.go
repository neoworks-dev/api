package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

var (
	ErrInvalidVerifier   = errors.New("code verifier does not match challenge")
	ErrUnsupportedMethod = errors.New("unsupported code challenge method")
)

func VerifyPKCE(verifier, challenge, method string) error {
	switch method {
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		if computed != challenge {
			return ErrInvalidVerifier
		}
		return nil
	case "plain":
		// plain is spec-valid but you should reject it for security
		return ErrUnsupportedMethod
	default:
		return ErrUnsupportedMethod
	}
}

