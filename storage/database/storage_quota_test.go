package database_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

func blobOf(size int) []byte {
	return []byte(`{"objectId":"` + uuid.NewString() + `","chunks":1,"size":` + strconv.Itoa(size) + `}`)
}

func (f *fixture) usedBytes(userID string) int64 {
	f.t.Helper()
	used, err := f.store.StorageUsedBytes(context.Background(), userID)
	if err != nil {
		f.t.Fatalf("storage used: %v", err)
	}
	return used
}

func (f *fixture) appUsedBytes(userID string, clientID string) int64 {
	f.t.Helper()
	used, err := f.store.AppStorageUsedBytes(context.Background(), userID, clientID)
	if err != nil {
		f.t.Fatalf("app storage used: %v", err)
	}
	return used
}

func (f *fixture) authorize(userID string, clientID string) {
	f.t.Helper()
	err := queryAll(context.Background(), f,
		"UPSERT grant SET user = $user, client = $client, scopes = [], enabled = true WHERE user = $user AND client = $client",
		map[string]any{"user": models.NewRecordID("user", userID), "client": models.NewRecordID("client", clientID)})
	if err != nil {
		f.t.Fatalf("authorize client: %v", err)
	}
}

func withClient(principal access.Principal, clientID string) access.Principal {
	principal.ClientID = clientID
	return principal
}

func contentOfLength(size int) string {
	return dbtest.Content(strings.Repeat("x", size))
}

func TestStorageCountsContentAndBlobOnCreateUpdateDeleteAndDetach(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := f.createRoot(owner, "@neoworks/photos")
	if used := f.usedBytes(owner.UserID); used != 0 {
		t.Fatalf("a root stores nothing: %d", used)
	}

	file := newNode(owner, owner.UserID, "@neoworks/photos", database.KindItem, &root.ID)
	file.Content = contentOfLength(50)
	file.Blob = blobOf(300)
	seq := f.pushOK(owner, file)
	created := int64(len(file.Content)) + 300
	if used := f.usedBytes(owner.UserID); used != created {
		t.Fatalf("after create: %d want %d", used, created)
	}

	file.BaseSeq = seq
	file.Content = contentOfLength(10)
	seq = f.pushOK(owner, file)
	updated := int64(len(file.Content)) + 300
	if used := f.usedBytes(owner.UserID); used != updated {
		t.Fatalf("after shrinking update: %d want %d", used, updated)
	}

	file.BaseSeq = seq
	file.Blob = nil
	seq = f.pushOK(owner, file)
	detached := int64(len(file.Content))
	if used := f.usedBytes(owner.UserID); used != detached {
		t.Fatalf("after detaching the blob: %d want %d", used, detached)
	}

	file.BaseSeq = seq
	file.Deleted = true
	f.pushOK(owner, file)
	if used := f.usedBytes(owner.UserID); used != 0 {
		t.Fatalf("after delete: %d want 0", used)
	}
}

func TestPushOverTheAccountQuotaIsRefusedAndShrinkingStillWorks(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := f.createRoot(owner, "@neoworks/photos")
	file := newNode(owner, owner.UserID, "@neoworks/photos", database.KindItem, &root.ID)
	file.Content = contentOfLength(20)
	seq := f.pushOK(owner, file)
	f.store.SetStorageQuota(int64(len(file.Content)) + 5)

	grown := file
	grown.BaseSeq = seq
	grown.Content = contentOfLength(60)
	if outcome := f.push(owner, grown); outcome.Status != database.StatusQuotaExceeded || outcome.LimitBytes != f.store.StorageQuotaBytes {
		t.Fatalf("growing past the quota: %+v", outcome)
	}
	if used := f.usedBytes(owner.UserID); used != int64(len(file.Content)) {
		t.Fatalf("a refused write changes nothing: %d", used)
	}

	second := newNode(owner, owner.UserID, "@neoworks/photos", database.KindItem, &root.ID)
	second.Content = contentOfLength(20)
	if outcome := f.push(owner, second); outcome.Status != database.StatusQuotaExceeded {
		t.Fatalf("creating past the quota: %s", outcome.Status)
	}

	shrunk := file
	shrunk.BaseSeq = seq
	shrunk.Content = contentOfLength(5)
	if outcome := f.push(owner, shrunk); outcome.Status != database.StatusOK {
		t.Fatalf("shrinking while at the quota: %s", outcome.Status)
	}
}

func TestBatchOverTheQuotaIsRefusedBeforeAnyNodeIsWritten(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := f.createRoot(owner, "@neoworks/photos")
	f.store.SetStorageQuota(100)
	batch := []*database.ValidatedNode{}
	for range 3 {
		node := newNode(owner, owner.UserID, "@neoworks/photos", database.KindItem, &root.ID)
		node.Content = contentOfLength(40)
		validated, err := database.ValidateNodeInput(node, owner)
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		batch = append(batch, validated)
	}
	var exceeded *database.QuotaError
	err := f.store.CheckPushQuota(context.Background(), owner, batch)
	if !errors.As(err, &exceeded) || exceeded.AppCap || exceeded.LimitBytes != 100 {
		t.Fatalf("batch check: %v", err)
	}
	f.store.SetStorageQuota(0)
	if err := f.store.CheckPushQuota(context.Background(), owner, batch); err != nil {
		t.Fatalf("no quota: %v", err)
	}
}

func TestSharedNodesCountAgainstTheirOwnerNotTheWriter(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	guest := f.createUser()
	root := f.createRoot(owner, "@neoworks/photos")
	f.grant(owner, root.ID, writeGrant(access.PrincipalTypeUser, guest.UserID, 1))

	shared := newNode(guest, owner.UserID, "@neoworks/photos", database.KindItem, &root.ID)
	shared.Content = contentOfLength(40)
	f.pushOK(guest, shared)

	if used := f.usedBytes(owner.UserID); used != int64(len(shared.Content)) {
		t.Fatalf("owner usage: %d", used)
	}
	if used := f.usedBytes(guest.UserID); used != 0 {
		t.Fatalf("the writer pays nothing: %d", used)
	}
	f.store.SetStorageQuota(10)
	more := newNode(guest, owner.UserID, "@neoworks/photos", database.KindItem, &root.ID)
	more.Content = contentOfLength(40)
	if outcome := f.push(guest, more); outcome.Status != database.StatusQuotaExceeded {
		t.Fatalf("the owner's quota binds the guest's write: %s", outcome.Status)
	}
}

func TestAppUsageIsAttributedToTheWritingAppAndItsCapBinds(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := f.createRoot(owner, "@neoworks/photos")
	songs := withClient(owner, "example-songs")
	photos := withClient(owner, "neoworks-photos")
	f.authorize(owner.UserID, "example-songs")
	f.authorize(owner.UserID, "neoworks-photos")

	first := newNode(songs, owner.UserID, "@neoworks/photos", database.KindItem, &root.ID)
	first.Content = contentOfLength(30)
	f.pushOK(songs, first)
	other := newNode(photos, owner.UserID, "@neoworks/photos", database.KindItem, &root.ID)
	other.Content = contentOfLength(90)
	f.pushOK(photos, other)

	if used := f.appUsedBytes(owner.UserID, "example-songs"); used != int64(len(first.Content)) {
		t.Fatalf("songs usage: %d", used)
	}
	if used := f.appUsedBytes(owner.UserID, "neoworks-photos"); used != int64(len(other.Content)) {
		t.Fatalf("photos usage: %d", used)
	}

	capBytes := int64(len(first.Content)) + 10
	if err := f.store.SetAppStorageCap(context.Background(), owner.UserID, "example-songs", &capBytes); err != nil {
		t.Fatalf("set cap: %v", err)
	}
	extra := newNode(songs, owner.UserID, "@neoworks/photos", database.KindItem, &root.ID)
	extra.Content = contentOfLength(30)
	outcome := f.push(songs, extra)
	if outcome.Status != database.StatusAppCapExceeded || outcome.LimitBytes != capBytes {
		t.Fatalf("writing past the cap: %+v", outcome)
	}
	if outcome := f.push(photos, extra); outcome.Status != database.StatusOK {
		t.Fatalf("another app is not bound by the cap: %s", outcome.Status)
	}
}

func TestStorageUsageListsAuthorizedAppsWithTheirCaps(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := f.createRoot(owner, "@neoworks/photos")
	f.authorize(owner.UserID, "example-songs")
	f.authorize(owner.UserID, "neoworks-photos")
	songs := withClient(owner, "example-songs")
	node := newNode(songs, owner.UserID, "@neoworks/photos", database.KindItem, &root.ID)
	f.pushOK(songs, node)
	capBytes := int64(1000)
	if err := f.store.SetAppStorageCap(context.Background(), owner.UserID, "neoworks-photos", &capBytes); err != nil {
		t.Fatalf("set cap: %v", err)
	}
	f.store.SetStorageQuota(5000)

	usage, err := f.store.GetStorageUsage(context.Background(), owner.UserID, "")
	if err != nil || usage.QuotaBytes != 5000 || usage.UsedBytes != int64(len(node.Content)) || len(usage.Apps) != 2 {
		t.Fatalf("usage: %+v %v", usage, err)
	}
	if usage.Apps[0].ClientID != "example-songs" || usage.Apps[0].UsedBytes != usage.UsedBytes || usage.Apps[0].CapBytes != nil {
		t.Fatalf("songs entry: %+v", usage.Apps[0])
	}
	if usage.Apps[1].CapBytes == nil || *usage.Apps[1].CapBytes != 1000 {
		t.Fatalf("photos entry: %+v", usage.Apps[1])
	}
	own, err := f.store.GetStorageUsage(context.Background(), owner.UserID, "example-songs")
	if err != nil || len(own.Apps) != 1 || own.Apps[0].ClientID != "example-songs" {
		t.Fatalf("an app sees only itself: %+v %v", own, err)
	}
	if err := f.store.SetAppStorageCap(context.Background(), owner.UserID, "never-authorized", &capBytes); !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("cap for an unauthorized app: %v", err)
	}
}
