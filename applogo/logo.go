// Package applogo validates and sanitizes the logo a developer uploads for an
// app. Logos are shown to users on the consent screen, so a logo must be a
// plain picture: PNG is re-encoded and SVG is rebuilt from an allowlist of
// elements and attributes, with no script and no reference outside the file.
package applogo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	ContentTypePNG = "image/png"
	ContentTypeSVG = "image/svg+xml"

	MaxPNGBytes    = 512 << 10
	MaxSVGBytes    = 64 << 10
	MinDimension   = 64
	MaxDimension   = 1024
	maxSVGDimens   = 4096
	maxAspectRatio = 4
)

var pngSignature = []byte("\x89PNG\r\n\x1a\n")

// ErrInvalid wraps every reason a logo is refused; its message is safe to show
// the developer.
var ErrInvalid = errors.New("invalid logo")

func invalid(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, arguments...))
}

// Logo is a validated logo ready to store.
type Logo struct {
	ContentType string
	Data        []byte
	// SHA256 identifies the sanitized bytes.
	SHA256 string
	// AHash is a perceptual hash of a PNG; empty for SVG.
	AHash string
}

// Validate sniffs the kind of the upload (the declared content type is not
// trusted), checks its limits and returns the sanitized logo.
func Validate(body []byte) (*Logo, error) {
	if len(body) == 0 {
		return nil, invalid("the logo is empty")
	}
	if bytes.HasPrefix(body, pngSignature) {
		return validatePNG(body)
	}
	return validateSVG(body)
}

func newLogo(contentType string, data []byte, aHash string) *Logo {
	digest := sha256.Sum256(data)
	return &Logo{ContentType: contentType, Data: data, SHA256: hex.EncodeToString(digest[:]), AHash: aHash}
}
