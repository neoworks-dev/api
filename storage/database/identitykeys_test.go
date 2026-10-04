package database

import (
	"errors"
	"testing"
	"time"
)

type signedThing struct {
	signedWith string
	issuedAt   time.Time
}

func verifyWithKey(thing signedThing) func(string) (*signedThing, error) {
	return func(signPub string) (*signedThing, error) {
		if signPub != thing.signedWith {
			return nil, errors.New("signature does not verify")
		}
		return &thing, nil
	}
}

func issuedAtOf(thing *signedThing) time.Time { return thing.issuedAt }

func TestHistoryAcceptsARetiredKeyForObjectsIssuedBeforeRetirement(t *testing.T) {
	retiredAt := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	keys := []IdentityKey{{Version: 1, SignPub: "old", RetiredAt: &retiredAt}, {Version: 2, SignPub: "new"}}

	before := signedThing{signedWith: "old", issuedAt: retiredAt.Add(-time.Hour)}
	if _, err := verifyUnderIdentityHistory(keys, issuedAtOf, verifyWithKey(before)); err != nil {
		t.Fatalf("issued before retirement: %v", err)
	}
	after := signedThing{signedWith: "old", issuedAt: retiredAt.Add(time.Hour)}
	if _, err := verifyUnderIdentityHistory(keys, issuedAtOf, verifyWithKey(after)); err == nil {
		t.Fatal("a retired identity must not issue after retiredAt")
	}
	current := signedThing{signedWith: "new", issuedAt: retiredAt.Add(time.Hour)}
	if _, err := verifyUnderIdentityHistory(keys, issuedAtOf, verifyWithKey(current)); err != nil {
		t.Fatalf("current identity: %v", err)
	}
	stranger := signedThing{signedWith: "other", issuedAt: retiredAt}
	if _, err := verifyUnderIdentityHistory(keys, issuedAtOf, verifyWithKey(stranger)); err == nil {
		t.Fatal("a key outside the history must not verify")
	}
}
