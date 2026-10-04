package utils

import (
	"crypto/rand"
	"strings"
)

// Contact codes are 12 Crockford base32 characters: 11 random characters and a
// check character. The check weights each character by an odd factor, so any
// single mistyped character is caught.
const (
	contactCodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	contactCodeLength   = 12
)

func contactCodeCheckCharacter(payload string) byte {
	sum := 0
	for position := 0; position < len(payload); position++ {
		value := strings.IndexByte(contactCodeAlphabet, payload[position])
		sum += value * (2*position + 1)
	}
	return contactCodeAlphabet[sum%32]
}

// GenerateContactCode returns a fresh canonical code (no hyphens).
func GenerateContactCode() (string, error) {
	random := make([]byte, contactCodeLength-1)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	payload := make([]byte, len(random))
	for position, value := range random {
		payload[position] = contactCodeAlphabet[value%32]
	}
	return string(payload) + string(contactCodeCheckCharacter(string(payload))), nil
}

// NormalizeContactCode strips separators, uppercases, maps the look-alike
// characters O, I and L, and verifies length, alphabet and check character.
func NormalizeContactCode(input string) (string, bool) {
	cleaned := strings.NewReplacer("-", "", " ", "").Replace(strings.ToUpper(input))
	cleaned = strings.NewReplacer("O", "0", "I", "1", "L", "1").Replace(cleaned)
	if len(cleaned) != contactCodeLength {
		return "", false
	}
	for position := 0; position < len(cleaned); position++ {
		if strings.IndexByte(contactCodeAlphabet, cleaned[position]) < 0 {
			return "", false
		}
	}
	payload := cleaned[:contactCodeLength-1]
	if cleaned[contactCodeLength-1] != contactCodeCheckCharacter(payload) {
		return "", false
	}
	return cleaned, true
}
