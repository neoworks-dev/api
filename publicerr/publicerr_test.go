package publicerr

import (
	"errors"
	"fmt"
	"testing"
)

func TestMessageUnwrapsPublicError(t *testing.T) {
	base := New("bad filter value")
	wrapped := fmt.Errorf("list contacts: %w", base)

	msg, ok := Message(wrapped)
	if !ok || msg != "bad filter value" {
		t.Fatalf("want public message through wrap, got %q ok=%v", msg, ok)
	}

	if _, ok := Message(errors.New("plain")); ok {
		t.Fatal("plain error must not be public")
	}
}

func TestClassifyDBErrorSanitizesKnownFailures(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"Failed to execute query: no index found for @@ on field", "this query needs an index that does not exist"},
		{"Found 'x' but expected a datetime value", "a date filter value is not a valid datetime"},
		{"The regular expression '[' is not valid", "a filter contains an invalid regular expression"},
	}
	for _, tc := range cases {
		msg, ok := ClassifyDBError(errors.New(tc.raw))
		if !ok {
			t.Fatalf("expected %q to classify", tc.raw)
		}
		if msg != tc.want {
			t.Fatalf("raw %q → %q, want %q", tc.raw, msg, tc.want)
		}
		if msg == tc.raw {
			t.Fatalf("classifier must not echo raw text: %q", msg)
		}
	}
}

func TestClassifyDBErrorDefaultDeny(t *testing.T) {
	if _, ok := ClassifyDBError(errors.New("record user:abc123 secret leaked")); ok {
		t.Fatal("unrecognized error must not be surfaced")
	}
	if _, ok := ClassifyDBError(nil); ok {
		t.Fatal("nil must not classify")
	}
}
