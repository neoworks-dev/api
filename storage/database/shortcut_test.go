package database_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
)

const photos = "@neoworks/photos"

// albumWithPhoto is an owner's photo library and album, with a photo in the
// library that the album will point at.
type albumWithPhoto struct {
	owner   access.Principal
	root    database.Node
	album   database.Node
	library database.Node
	photo   database.Node
}

func newAlbumWithPhoto(f *fixture) albumWithPhoto {
	f.t.Helper()
	owner := f.createUser()
	root := f.createRoot(owner, photos)
	library := newNode(owner, owner.UserID, photos, database.KindContainer, &root.ID)
	album := newNode(owner, owner.UserID, photos, database.KindContainer, &root.ID)
	f.pushOK(owner, library)
	f.pushOK(owner, album)
	photo := newNode(owner, owner.UserID, photos, database.KindItem, &library.ID)
	f.pushOK(owner, photo)
	return albumWithPhoto{owner: owner, root: root, album: album, library: library, photo: photo}
}

func shortcutTo(author access.Principal, ownerID string, parentID *string, target database.Node, role string) database.Node {
	shortcut := newNode(author, ownerID, target.Collection, database.KindItem, parentID)
	shortcut.Content = ""
	shortcut.TargetID, shortcut.TargetRole = &target.ID, &role
	return shortcut
}

func TestASharedAlbumMakesItsShortcutTargetsReadable(t *testing.T) {
	f := newFixture(t)
	scene := newAlbumWithPhoto(f)
	viewer := f.createUser()
	shortcut := shortcutTo(scene.owner, scene.owner.UserID, &scene.album.ID, scene.photo, access.RoleRead)
	f.pushOK(scene.owner, shortcut)
	f.grant(scene.owner, scene.album.ID, readGrant(access.PrincipalTypeUser, viewer.UserID, 1))

	seen := nodeIDs(f.pull(viewer, 0, 50).Nodes)
	if !seen[scene.album.ID] || !seen[shortcut.ID] || !seen[scene.photo.ID] {
		t.Fatalf("viewer should see the album, the shortcut and the photo: %v", seen)
	}
	if seen[scene.library.ID] {
		t.Fatal("the shortcut must not reveal the library it points into")
	}
	if _, err := f.store.ListNodeVersions(context.Background(), viewer, scene.photo.ID); err != nil {
		t.Fatalf("the photo's history is readable through the shortcut: %v", err)
	}
	edit := scene.photo
	edit.AuthorID = viewer.UserID
	edit.BaseSeq = f.nodeSeq(f.pull(scene.owner, 0, 50), scene.photo.ID)
	if outcome := f.push(viewer, edit); outcome.Status != database.StatusForbidden {
		t.Fatalf("a read shortcut must not let the viewer write the photo: got %s", outcome.Status)
	}
}

func TestAWriteShortcutLetsAnAlbumWriterEditTheTarget(t *testing.T) {
	f := newFixture(t)
	scene := newAlbumWithPhoto(f)
	editor := f.createUser()
	f.pushOK(scene.owner, shortcutTo(scene.owner, scene.owner.UserID, &scene.album.ID, scene.photo, access.RoleWrite))
	f.grant(scene.owner, scene.album.ID, writeGrant(access.PrincipalTypeUser, editor.UserID, 1))

	edit := scene.photo
	edit.AuthorID = editor.UserID
	edit.BaseSeq = f.nodeSeq(f.pull(editor, 0, 50), scene.photo.ID)
	edit.Content = dbtest.Content("edited")
	if outcome := f.push(editor, edit); outcome.Status != database.StatusOK {
		t.Fatalf("a write shortcut held with write should allow editing the photo: got %s", outcome.Status)
	}
}

func TestShortcutTargetsMustBeLiveItemsTheWriterMayPassOn(t *testing.T) {
	f := newFixture(t)
	scene := newAlbumWithPhoto(f)
	owner := scene.owner
	readable := shortcutTo(owner, owner.UserID, &scene.album.ID, scene.photo, access.RoleRead)
	f.pushOK(owner, readable)

	refused := map[string]database.Node{
		"a container":    shortcutTo(owner, owner.UserID, &scene.album.ID, scene.library, access.RoleRead),
		"a shortcut":     shortcutTo(owner, owner.UserID, &scene.album.ID, readable, access.RoleRead),
		"a missing item": shortcutTo(owner, owner.UserID, &scene.album.ID, database.Node{ID: uuid.NewString(), Collection: photos}, access.RoleRead),
	}
	calendarRoot := f.createRoot(owner, "@neoworks/calendar")
	elsewhere := shortcutTo(owner, owner.UserID, &calendarRoot.ID, scene.photo, access.RoleRead)
	elsewhere.Collection = "@neoworks/calendar"
	refused["an item of another collection"] = elsewhere
	for name, shortcut := range refused {
		if outcome := f.push(owner, shortcut); outcome.Status != database.StatusForbidden {
			t.Fatalf("a shortcut to %s: got %s want forbidden", name, outcome.Status)
		}
	}
}

func TestAReaderCannotPassOnWriteThroughItsOwnShortcut(t *testing.T) {
	f := newFixture(t)
	scene := newAlbumWithPhoto(f)
	viewer := f.createUser()
	f.pushOK(scene.owner, shortcutTo(scene.owner, scene.owner.UserID, &scene.album.ID, scene.photo, access.RoleRead))
	f.grant(scene.owner, scene.album.ID, readGrant(access.PrincipalTypeUser, viewer.UserID, 1))
	viewerRoot := f.createRoot(viewer, photos)

	write := shortcutTo(viewer, viewer.UserID, &viewerRoot.ID, scene.photo, access.RoleWrite)
	if outcome := f.push(viewer, write); outcome.Status != database.StatusForbidden {
		t.Fatalf("a reader handing out write: got %s want forbidden", outcome.Status)
	}
	read := shortcutTo(viewer, viewer.UserID, &viewerRoot.ID, scene.photo, access.RoleRead)
	if outcome := f.push(viewer, read); outcome.Status != database.StatusOK {
		t.Fatalf("a reader keeping a read shortcut in its own tree: got %s want ok", outcome.Status)
	}
}

func TestAShortcutKeepsItsTarget(t *testing.T) {
	f := newFixture(t)
	scene := newAlbumWithPhoto(f)
	owner := scene.owner
	other := newNode(owner, owner.UserID, photos, database.KindItem, &scene.library.ID)
	f.pushOK(owner, other)
	shortcut := shortcutTo(owner, owner.UserID, &scene.album.ID, scene.photo, access.RoleRead)
	seq := f.pushOK(owner, shortcut)

	retargeted := shortcut
	retargeted.BaseSeq = seq
	retargeted.TargetID = &other.ID
	if outcome := f.push(owner, retargeted); outcome.Status != database.StatusForbidden {
		t.Fatalf("changing a shortcut's target: got %s want forbidden", outcome.Status)
	}
	promoted := shortcut
	promoted.BaseSeq = seq
	write := access.RoleWrite
	promoted.TargetRole = &write
	if outcome := f.push(owner, promoted); outcome.Status != database.StatusForbidden {
		t.Fatalf("changing a shortcut's role: got %s want forbidden", outcome.Status)
	}
}

func TestANewShortcutBringsAnOldTargetIntoTheNextPull(t *testing.T) {
	f := newFixture(t)
	scene := newAlbumWithPhoto(f)
	viewer := f.createUser()
	f.grant(scene.owner, scene.album.ID, readGrant(access.PrincipalTypeUser, viewer.UserID, 1))
	cursor := f.pull(viewer, 0, 50).Cursor

	shortcut := shortcutTo(scene.owner, scene.owner.UserID, &scene.album.ID, scene.photo, access.RoleRead)
	seq := f.pushOK(scene.owner, shortcut)
	if seen := nodeIDs(f.pull(viewer, cursor, 50).Nodes); !seen[scene.photo.ID] {
		t.Fatalf("the incremental pull carrying the shortcut should carry its target: %v", seen)
	}

	shortcut.BaseSeq, shortcut.Deleted = seq, true
	f.pushOK(scene.owner, shortcut)
	if seen := nodeIDs(f.pull(viewer, 0, 50).Nodes); seen[scene.photo.ID] {
		t.Fatal("a deleted shortcut must stop exposing its target")
	}
}

func TestANewRootNeedsAPublishedNodeSchema(t *testing.T) {
	f := newFixture(t)
	owner := f.createUser()
	owner.Scopes = append(owner.Scopes, "@nobody/unpublished:write")
	root := newNode(owner, owner.UserID, "@nobody/unpublished", database.KindRoot, nil)
	if outcome := f.push(owner, root); outcome.Status != database.StatusForbidden {
		t.Fatalf("a root in an unpublished collection: got %s want forbidden", outcome.Status)
	}
}
