package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
)

func GenerateRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing is a "stop the process" event
	}
	return base64.RawURLEncoding.EncodeToString(b)[:length]
}

// GenerateNumericCode returns a zero-padded decimal code of the given length,
// e.g. "048213" for a 6-digit code. Used for email verification codes.
func GenerateNumericCode(digits int) string {
	upperBound := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)
	n, err := rand.Int(rand.Reader, upperBound)
	if err != nil {
		panic(err) // crypto/rand failing is a "stop the process" event
	}
	return fmt.Sprintf("%0*d", digits, n)
}
