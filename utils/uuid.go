package utils

import "regexp"

var lowercaseUUIDv4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// IsLowercaseUUIDv4 reports whether value has the shape of every client-chosen id.
func IsLowercaseUUIDv4(value string) bool {
	return lowercaseUUIDv4.MatchString(value)
}
