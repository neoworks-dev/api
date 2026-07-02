package cache

import (
	"slices"
	"testing"
)

func TestDecodeAccountsJSONList(t *testing.T) {
	got := decodeAccounts(`["user:a","user:b"]`)
	want := []string{"user:a", "user:b"}
	if !slices.Equal(got, want) {
		t.Fatalf("decodeAccounts = %v, want %v", got, want)
	}
}

// Sessions written before multi-account support held a bare user id; they must
// still resolve so existing logins are not invalidated on deploy.
func TestDecodeAccountsLegacyBareID(t *testing.T) {
	got := decodeAccounts("user:legacy")
	want := []string{"user:legacy"}
	if !slices.Equal(got, want) {
		t.Fatalf("decodeAccounts = %v, want %v", got, want)
	}
}

func TestMoveToFrontAddsNewActive(t *testing.T) {
	got := moveToFront([]string{"user:a", "user:b"}, "user:c")
	want := []string{"user:c", "user:a", "user:b"}
	if !slices.Equal(got, want) {
		t.Fatalf("moveToFront = %v, want %v", got, want)
	}
}

// Re-selecting an existing account must promote it without duplicating it.
func TestMoveToFrontDedupesExisting(t *testing.T) {
	got := moveToFront([]string{"user:a", "user:b", "user:c"}, "user:c")
	want := []string{"user:c", "user:a", "user:b"}
	if !slices.Equal(got, want) {
		t.Fatalf("moveToFront = %v, want %v", got, want)
	}
}

func TestMoveToFrontFromEmpty(t *testing.T) {
	got := moveToFront(nil, "user:a")
	want := []string{"user:a"}
	if !slices.Equal(got, want) {
		t.Fatalf("moveToFront = %v, want %v", got, want)
	}
}
