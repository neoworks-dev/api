package database_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/database"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

func TestInstallActsOnlyThroughItsGrantAndCertificate(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := f.createRoot(owner, "calendar")
	app, certID := f.createInstall(owner, "calendar:read", "calendar:write")

	child := newNode(app, owner.UserID, "calendar", database.KindItem, &root.ID)
	child.CertID = &certID
	if outcome := f.push(app, child); outcome.Status != database.StatusForbidden {
		t.Fatalf("install without grant: got %s want forbidden", outcome.Status)
	}

	shared := writeGrant(access.PrincipalTypeInstall, app.InstallID, 1)
	f.grant(owner, root.ID, shared)
	if outcome := f.push(app, child); outcome.Status != database.StatusOK {
		t.Fatalf("install with grant: got %s want ok", outcome.Status)
	}

	_, otherCert := f.createInstall(owner, "calendar:write")
	forged := newNode(app, owner.UserID, "calendar", database.KindItem, &root.ID)
	forged.CertID = &otherCert
	if outcome := f.push(app, forged); outcome.Status != database.StatusForbidden {
		t.Fatalf("another install's certificate: got %s want forbidden", outcome.Status)
	}
}

func TestInstallTokenScopeCapsItsWriteGrant(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := f.createRoot(owner, "calendar")
	app, certID := f.createInstall(owner, "calendar:read")
	shared := writeGrant(access.PrincipalTypeInstall, app.InstallID, 1)
	f.grant(owner, root.ID, shared)

	child := newNode(app, owner.UserID, "calendar", database.KindItem, &root.ID)
	child.CertID = &certID
	if outcome := f.push(app, child); outcome.Status != database.StatusForbidden {
		t.Fatalf("read-scoped install with write grant: got %s want forbidden", outcome.Status)
	}
	if page := f.pull(app, 0, 10); len(page.Nodes) != 1 {
		t.Fatalf("read-scoped install should still pull the root, got %d nodes", len(page.Nodes))
	}
}

func TestWriterCannotClaimAnotherOwnerOrCollection(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	writer := f.createUser()
	root := f.createRoot(owner, "calendar")
	shared := writeGrant(access.PrincipalTypeUser, writer.UserID, 1)
	f.grant(owner, root.ID, shared)

	ownsItself := newNode(writer, writer.UserID, "calendar", database.KindItem, &root.ID)
	if outcome := f.push(writer, ownsItself); outcome.Status != database.StatusForbidden {
		t.Fatalf("child claiming a different owner: got %s want forbidden", outcome.Status)
	}
	wrongCollection := newNode(writer, owner.UserID, "photos", database.KindItem, &root.ID)
	if outcome := f.push(writer, wrongCollection); outcome.Status != database.StatusForbidden {
		t.Fatalf("child in another collection: got %s want forbidden", outcome.Status)
	}
}

func TestOnlyTheUserCanCreateTheirOwnRoot(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	other := f.createUser()
	app, certID := f.createInstall(owner, "calendar:write")

	foreign := newNode(other, owner.UserID, "calendar", database.KindRoot, nil)
	if outcome := f.push(other, foreign); outcome.Status != database.StatusForbidden {
		t.Fatalf("root for another user: got %s want forbidden", outcome.Status)
	}
	byInstall := newNode(app, owner.UserID, "calendar", database.KindRoot, nil)
	byInstall.CertID = &certID
	if outcome := f.push(app, byInstall); outcome.Status != database.StatusForbidden {
		t.Fatalf("root by install: got %s want forbidden", outcome.Status)
	}
}

func TestMovingIntoOwnSubtreeIsRejected(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := f.createRoot(owner, "calendar")
	outer := newNode(owner, owner.UserID, "calendar", database.KindContainer, &root.ID)
	f.pushOK(owner, outer)
	inner := newNode(owner, owner.UserID, "calendar", database.KindContainer, &outer.ID)
	f.pushOK(owner, inner)

	moved := outer
	moved.ParentID = &inner.ID
	moved.BaseSeq = f.nodeSeq(f.pull(owner, 0, 50), outer.ID)
	if outcome := f.push(owner, moved); outcome.Status != database.StatusForbidden {
		t.Fatalf("cycle: got %s want forbidden", outcome.Status)
	}
}

func TestItemsCannotHaveChildren(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := f.createRoot(owner, "calendar")
	item := newNode(owner, owner.UserID, "calendar", database.KindItem, &root.ID)
	f.pushOK(owner, item)

	child := newNode(owner, owner.UserID, "calendar", database.KindItem, &item.ID)
	if outcome := f.push(owner, child); outcome.Status != database.StatusForbidden {
		t.Fatalf("child of an item: got %s want forbidden", outcome.Status)
	}
}

func TestStrangerCannotReadHistoryOrCertificate(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	stranger := f.createUser()
	root := f.createRoot(owner, "calendar")
	app, certID := f.createInstall(owner, "calendar:write")
	shared := writeGrant(access.PrincipalTypeInstall, app.InstallID, 1)
	f.grant(owner, root.ID, shared)
	item := newNode(app, owner.UserID, "calendar", database.KindItem, &root.ID)
	item.CertID = &certID
	f.pushOK(app, item)

	if _, err := f.store.ListNodeVersions(context.Background(), stranger, item.ID); !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("stranger history: got %v want not found", err)
	}
	if _, err := f.store.CertificateForPrincipal(context.Background(), stranger, certID); !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("stranger certificate: got %v want not found", err)
	}

	f.grant(owner, root.ID, readGrant(access.PrincipalTypeUser, stranger.UserID, 1))
	if _, err := f.store.CertificateForPrincipal(context.Background(), stranger, certID); err != nil {
		t.Fatalf("a reader of the install's node may fetch its certificate: %v", err)
	}
}

func TestTombstonePurgeRaisesHorizonAnd410(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := f.createRoot(owner, "calendar")
	keep := newNode(owner, owner.UserID, "calendar", database.KindItem, &root.ID)
	f.pushOK(owner, keep)
	doomed := newNode(owner, owner.UserID, "calendar", database.KindItem, &root.ID)
	seq := f.pushOK(owner, doomed)
	doomed.BaseSeq = seq
	doomed.Deleted = true
	doomed.Content = nil
	deletedSeq := f.pushOK(owner, doomed)

	staleCursor := deletedSeq - 1
	result, err := f.store.PurgeTombstones(context.Background(), -time.Minute)
	if err != nil || result.Nodes != 1 {
		t.Fatalf("purge: nodes %d err %v", result.Nodes, err)
	}

	_, err = f.store.Pull(context.Background(), owner, staleCursor, 10)
	var purged *database.PurgedError
	if !errors.As(err, &purged) || purged.Horizon != deletedSeq {
		t.Fatalf("stale cursor: got %v want PurgedError at %d", err, deletedSeq)
	}
	if _, err := f.store.Pull(context.Background(), owner, 0, 10); err != nil {
		t.Fatalf("a full sync from 0 must always work: %v", err)
	}
	if _, err := f.store.Pull(context.Background(), owner, deletedSeq, 10); err != nil {
		t.Fatalf("cursor at the horizon is current: %v", err)
	}
	if ids := nodeIDs(f.pull(owner, 0, 10).Nodes); ids[doomed.ID] || !ids[keep.ID] {
		t.Fatalf("purge should drop only the tombstone, got %v", ids)
	}
	if versions, _ := f.store.ListNodeVersions(context.Background(), owner, keep.ID); len(versions) != 1 {
		t.Fatalf("kept node lost history: %d versions", len(versions))
	}
}

func TestPurgeReportsOnlyUnreferencedObjects(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	root := f.createRoot(owner, "files")
	objectID := uuid.NewString()
	file := newNode(owner, owner.UserID, "files", database.KindItem, &root.ID)
	file.Blob = []byte(`{"objectId":"` + objectID + `","chunks":1,"size":50}`)
	seq := f.pushOK(owner, file)
	file.BaseSeq = seq
	file.Deleted = true
	f.pushOK(owner, file)

	result, err := f.store.PurgeTombstones(context.Background(), -time.Minute)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if len(result.UnreferencedObjects) != 1 || result.UnreferencedObjects[0] != objectID {
		t.Fatalf("unreferenced objects: %v", result.UnreferencedObjects)
	}
}

func TestRevokingAnInstallStopsItsTokensAndFlagsRotation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	owner := f.createUser()
	root := f.createRoot(owner, "calendar")
	app, _ := f.createInstall(owner, "calendar:write")
	shared := readGrant(access.PrincipalTypeInstall, app.InstallID, 1)
	f.grant(owner, root.ID, shared)

	refresh := oauth.RefreshToken{
		ID:        &models.RecordID{Table: "refresh_token", ID: uuid.NewString()},
		User:      &models.RecordID{Table: "user", ID: owner.UserID},
		Client:    &models.RecordID{Table: "client", ID: "neoworks-calendar"},
		Install:   &models.RecordID{Table: "install", ID: app.InstallID},
		Scopes:    []string{"calendar:write"},
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	if err := f.store.SaveRefreshToken(ctx, refresh); err != nil {
		t.Fatalf("save refresh token: %v", err)
	}

	if err := f.store.RevokeInstall(ctx, owner.UserID, app.InstallID); err != nil {
		t.Fatalf("revoke install: %v", err)
	}
	stored, err := f.store.GetRefreshToken(ctx, refresh.ID.ID.(string))
	if err != nil || !stored.Revoked {
		t.Fatalf("refresh token should be revoked: %+v %v", stored, err)
	}
	install, err := f.store.GetInstall(ctx, app.InstallID)
	if err != nil || install.RevokedAt == nil {
		t.Fatalf("install not marked revoked: %+v %v", install, err)
	}
	if !f.pull(owner, 0, 10).Nodes[0].NeedsRotation {
		t.Fatal("the granted node should need rotation")
	}
	f.revoke(owner, root.ID, access.PrincipalTypeInstall, app.InstallID)
	if page := f.pull(app, 0, 10); len(page.Nodes) != 0 {
		t.Fatalf("an install whose grant the owner revoked still pulls %d nodes", len(page.Nodes))
	}
	stranger := f.createUser()
	if err := f.store.RevokeInstall(ctx, stranger.UserID, app.InstallID); !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("revoking another user's install: got %v want not found", err)
	}
}

func TestRotationClearsNeedsRotationWhenEpochAdvances(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	reader := f.createUser()
	root := f.createRoot(owner, "calendar")
	shared := readGrant(access.PrincipalTypeUser, reader.UserID, 1)
	f.grant(owner, root.ID, shared)
	f.revoke(owner, root.ID, access.PrincipalTypeUser, reader.UserID)

	rotated := root
	rotated.Epoch = 2
	rotated.BaseSeq = f.nodeSeq(f.pull(owner, 0, 10), root.ID)
	f.pushOK(owner, rotated)
	if f.pull(owner, 0, 10).Nodes[0].NeedsRotation {
		t.Fatal("a write at a higher epoch should clear needsRotation")
	}
}

func TestLinkPullServesOnlyTheLinkedSubtree(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	owner := f.createUser()
	root := f.createRoot(owner, "photos")
	album := newNode(owner, owner.UserID, "photos", database.KindContainer, &root.ID)
	f.pushOK(owner, album)
	photo := newNode(owner, owner.UserID, "photos", database.KindItem, &album.ID)
	f.pushOK(owner, photo)
	other := newNode(owner, owner.UserID, "photos", database.KindContainer, &root.ID)
	f.pushOK(owner, other)

	link, err := f.store.CreateLink(ctx, owner, album.ID)
	if err != nil {
		t.Fatalf("create link: %v", err)
	}
	page, err := f.store.PullLink(ctx, link.ID, 0, 50)
	if err != nil {
		t.Fatalf("pull link: %v", err)
	}
	ids := nodeIDs(page.Nodes)
	if !ids[album.ID] || !ids[photo.ID] || ids[other.ID] || ids[root.ID] {
		t.Fatalf("link subtree wrong: %v", ids)
	}

	reader := f.createUser()
	if _, err := f.store.CreateLink(ctx, reader, album.ID); !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("non-admin link creation: got %v want not found", err)
	}
	if err := f.store.RevokeLink(ctx, owner, link.ID); err != nil {
		t.Fatalf("revoke link: %v", err)
	}
	if _, err := f.store.PullLink(ctx, link.ID, 0, 50); !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("revoked link: got %v want not found", err)
	}
}

func TestABlobObjectBelongsToOneNode(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	other := f.createUser()
	ownerRoot := f.createRoot(owner, "files")
	otherRoot := f.createRoot(other, "files")
	objectID := uuid.NewString()
	blob := []byte(`{"objectId":"` + objectID + `","chunks":1,"size":10}`)

	mine := newNode(owner, owner.UserID, "files", database.KindItem, &ownerRoot.ID)
	mine.Blob = blob
	seq := f.pushOK(owner, mine)

	stolen := newNode(other, other.UserID, "files", database.KindItem, &otherRoot.ID)
	stolen.Blob = blob
	if outcome := f.push(other, stolen); outcome.Status != database.StatusForbidden {
		t.Fatalf("claiming another node's object: got %s want forbidden", outcome.Status)
	}

	mine.BaseSeq = seq
	mine.Content = []database.FacetContent{{Facet: 0, Ciphertext: "renamed"}}
	if outcome := f.push(owner, mine); outcome.Status != database.StatusOK {
		t.Fatalf("rewriting a node with its own object: got %s want ok", outcome.Status)
	}
}
