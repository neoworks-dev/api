package database_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/neoworks/auth/storage/database"
)

func TestKeyBundleRotationRequiresTheNextVersion(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	owner := f.createUser()
	current, err := f.store.GetKeyBundle(ctx, owner.UserID)
	if err != nil || current.Version != 1 {
		t.Fatalf("initial bundle: %+v %v", current, err)
	}

	next := *current
	next.Version = 2
	next.AmkPassword = "rewrapped"
	if err := f.store.RotateKeyBundle(ctx, owner.UserID, 1, next, nil); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	err = f.store.RotateKeyBundle(ctx, owner.UserID, 1, next, nil)
	var mismatch *database.ErrBundleVersionMismatch
	if !errors.As(err, &mismatch) || mismatch.CurrentVersion != 2 {
		t.Fatalf("stale rotation: got %v want mismatch at version 2", err)
	}
	stored, _ := f.store.GetKeyBundle(ctx, owner.UserID)
	if stored.AmkPassword != "rewrapped" || stored.Version != 2 {
		t.Fatalf("bundle not swapped: %+v", stored)
	}
}

func TestIdentityLookupByEmailAndID(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	owner := f.createUser()
	byID, err := f.store.GetPublicIdentityByUserID(ctx, owner.UserID)
	if err != nil || byID.SignPub == "" {
		t.Fatalf("by id: %+v %v", byID, err)
	}
	user, _ := f.store.GetUserByID(ctx, owner.UserID)
	byEmail, err := f.store.GetPublicIdentityByEmail(ctx, user.Email)
	if err != nil || byEmail.UserID != owner.UserID {
		t.Fatalf("by email: %+v %v", byEmail, err)
	}
	if _, err := f.store.GetPublicIdentityByUserID(ctx, uuid.NewString()); !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("unknown user: got %v want not found", err)
	}
}

func TestDeviceRevocationIsScopedToTheOwner(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	owner := f.createUser()
	stranger := f.createUser()
	device, err := f.store.RegisterDevice(ctx, owner.UserID, &database.RegisterDeviceParams{Name: "laptop", Kind: database.DeviceKindBrowser})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := f.store.RevokeDevice(ctx, stranger.UserID, device.ID); !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("stranger revoke: got %v want not found", err)
	}
	if err := f.store.RevokeDevice(ctx, owner.UserID, device.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	devices, _ := f.store.ListDevices(ctx, owner.UserID)
	if len(devices) != 1 || devices[0].RevokedAt == nil {
		t.Fatalf("device not revoked: %+v", devices)
	}
}
