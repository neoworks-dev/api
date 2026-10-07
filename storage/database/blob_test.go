package database_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/neoworks/auth/storage/database"
)

func TestStorageUsageCountsLiveBlobsOnly(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := f.createRoot(owner, "@neoworks/files")
	file := newNode(owner, owner.UserID, "@neoworks/files", database.KindItem, &root.ID)
	file.Blob = []byte(`{"objectId":"` + uuid.NewString() + `","chunks":1,"size":70}`)
	seq := f.pushOK(owner, file)

	used, err := f.store.StorageUsedBytes(context.Background(), owner.UserID)
	if err != nil || used != 70 {
		t.Fatalf("usage: %d %v", used, err)
	}
	file.BaseSeq = seq
	file.Deleted = true
	f.pushOK(owner, file)
	if used, _ := f.store.StorageUsedBytes(context.Background(), owner.UserID); used != 0 {
		t.Fatalf("usage after delete: %d", used)
	}
}

func TestAnAlbumGranteeDownloadsThroughTheReferenceNode(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	recipient := f.createUser()
	root := f.createRoot(owner, "@neoworks/photos")
	album := newNode(owner, owner.UserID, "@neoworks/photos", database.KindContainer, &root.ID)
	f.pushOK(owner, album)
	objectID := uuid.NewString()
	original := newNode(owner, owner.UserID, "@neoworks/photos", database.KindItem, &root.ID)
	original.Blob = []byte(`{"objectId":"` + objectID + `","chunks":2,"size":50}`)
	f.pushOK(owner, original)
	reference := newNode(owner, owner.UserID, "@neoworks/photos", database.KindItem, &album.ID)
	reference.Blob = []byte(`{"objectId":"` + objectID + `","chunks":2,"size":0}`)
	f.pushOK(owner, reference)
	f.grant(owner, album.ID, readGrant("user", recipient.UserID, 1))

	ctx := context.Background()
	target, err := f.store.AuthorizeBlob(ctx, recipient, reference.ID, objectID, false)
	if err != nil || target.Chunks != 2 || target.OwnerID != owner.UserID {
		t.Fatalf("download through the reference: %+v %v", target, err)
	}
	if _, err := f.store.AuthorizeBlob(ctx, recipient, original.ID, objectID, false); err == nil {
		t.Fatal("the album grant must not open the original photo node")
	}
	if _, err := f.store.AuthorizeBlob(ctx, recipient, reference.ID, objectID, true); err == nil {
		t.Fatal("a read grant must not upload through the reference")
	}
}
