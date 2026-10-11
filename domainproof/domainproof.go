// Package domainproof checks that an owner controls a domain: the domain
// publishes the owner's token in a DNS TXT record on the domain itself, or as
// the body of a file under /.well-known/. The lookups sit behind Prover so
// tests never touch the network.
package domainproof

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"github.com/neoworks/auth/storage/database"
)

const (
	// TokenPrefix starts every token, so a TXT record is recognizable among others.
	TokenPrefix = "neoworks-verify="
	// WellKnownPath is where the file method serves the token over https.
	WellKnownPath = "/.well-known/neoworks-verification.txt"

	maxDomainLength = 253
)

// Prover looks up what a domain publishes.
type Prover interface {
	// LookupTXT returns the TXT records of the name.
	LookupTXT(ctx context.Context, name string) ([]string, error)
	// FetchWellKnown returns the body of the verification file served by the domain.
	FetchWellKnown(ctx context.Context, domain string) (string, error)
}

var labelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeDomain lowercases a domain and reports whether it is a plain
// hostname of at least two labels: no scheme, port, path or IP address.
func NormalizeDomain(input string) (string, bool) {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(input), "."))
	if domain == "" || len(domain) > maxDomainLength {
		return "", false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 || isNumeric(labels[len(labels)-1]) {
		return "", false
	}
	for _, label := range labels {
		if !labelPattern.MatchString(label) {
			return "", false
		}
	}
	return domain, true
}

func isNumeric(label string) bool {
	for _, character := range label {
		if character < '0' || character > '9' {
			return false
		}
	}
	return label != ""
}

// NewToken returns a fresh token for a domain to publish.
func NewToken() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return TokenPrefix + hex.EncodeToString(random), nil
}

// Check reports whether the domain publishes the token by the method. An error
// means the lookup itself failed; a domain that simply does not publish the
// token is (false, nil).
func Check(ctx context.Context, prover Prover, method string, domain string, token string) (bool, error) {
	switch method {
	case database.DomainMethodDNS:
		return checkDNS(ctx, prover, domain, token)
	case database.DomainMethodWellKnown:
		return checkWellKnown(ctx, prover, domain, token)
	}
	return false, errors.New("unknown verification method " + method)
}

func checkDNS(ctx context.Context, prover Prover, domain string, token string) (bool, error) {
	records, err := prover.LookupTXT(ctx, domain)
	if err != nil {
		return false, err
	}
	for _, record := range records {
		if strings.TrimSpace(record) == token {
			return true, nil
		}
	}
	return false, nil
}

func checkWellKnown(ctx context.Context, prover Prover, domain string, token string) (bool, error) {
	body, err := prover.FetchWellKnown(ctx, domain)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(body) == token, nil
}
