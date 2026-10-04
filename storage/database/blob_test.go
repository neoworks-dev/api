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
	root := f.createRoot(owner, "files")
	file := newNode(owner, owner.UserID, "files", database.KindItem, &root.ID)
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
