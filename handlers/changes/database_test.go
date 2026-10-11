package changes_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/handlers/changes"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
)

// These tests run the feed against a real database: the live queries, the
// recipient lookups and the catch-up check all go through the store.

type liveFixture struct {
	*feedServer
	store *database.SurrealStore
}

func newLiveFixture(t *testing.T) *liveFixture {
	t.Helper()
	store := dbtest.New(t)
	feed := changes.StoreFeed{SurrealStore: store}
	hub := changes.NewHub(feed).WithLimits(fastLimits)
	router := chi.NewRouter()
	router.Group(func(authenticated chi.Router) {
		authenticated.Use(signIn)
		changes.NewHandler(hub, feed, newTestLeases(t)).RegisterAuthenticated(authenticated)
	})
	server := httptest.NewServer(router)
	hub.Start()
	t.Cleanup(func() {
		hub.Shutdown()
		server.Close()
	})
	waitUntilWatching(t, hub)
	return &liveFixture{feedServer: &feedServer{server: server, hub: hub}, store: store}
}

func waitUntilWatching(t *testing.T, hub *changes.Hub) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !hub.Watching() {
		if time.Now().After(deadline) {
			t.Fatal("the hub never started watching")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (fixture *liveFixture) pushNode(t *testing.T, author access.Principal, ownerID string, kind string, parentID *string) database.Node {
	t.Helper()
	node := database.Node{
		ID: uuid.NewString(), ParentID: parentID, OwnerID: ownerID, Collection: photos, Kind: kind, Epoch: 1,
		AuthorType: author.Type(), AuthorID: author.ID(), Signature: "sig",
	}
	if kind != database.KindRoot {
		wrapped := "wrapped"
		node.WrappedKey = &wrapped
		node.Content = dbtest.Content("ciphertext")
	}
	validated, err := database.ValidateNodeInput(node, author)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	outcome, err := fixture.store.PushNode(context.Background(), author, validated)
	if err != nil || outcome.Status != database.StatusOK {
		t.Fatalf("push: %v %v", outcome, err)
	}
	return node
}

// nextChange reads events until a change arrives; the feed also sends a resync
// when the hub starts, which streams may or may not see.
func (stream *sseStream) nextChange(t *testing.T) event {
	t.Helper()
	for {
		received := stream.next(t)
		if received.name == "change" {
			return received
		}
	}
}

func TestPushReachesOwnerAndGrantHolderButNotStrangersOrOtherScopes(t *testing.T) {
	fixture := newLiveFixture(t)
	owner := dbtest.CreateAccount(t, fixture.store)
	viewer := dbtest.CreateAccount(t, fixture.store)
	stranger := dbtest.CreateAccount(t, fixture.store)
	root := fixture.pushNode(t, owner.Principal, owner.Principal.UserID, database.KindRoot, nil)
	owner.Grant(t, fixture.store, root.ID, dbtest.WriteGrant("user", owner.Principal.UserID, 1))

	ownerStream := fixture.open(t, clientOptions{userID: owner.Principal.UserID, scopes: photos + ":write"})
	viewerStream := fixture.open(t, clientOptions{userID: viewer.Principal.UserID, scopes: photos + ":read"})
	viewerWithoutScope := fixture.open(t, clientOptions{userID: viewer.Principal.UserID, scopes: calendar + ":read"})
	strangerStream := fixture.open(t, clientOptions{userID: stranger.Principal.UserID, scopes: photos + ":read"})
	owner.Grant(t, fixture.store, root.ID, dbtest.ReadGrant("user", viewer.Principal.UserID, 1))
	viewerStream.nextChange(t)
	ownerStream.nextChange(t)

	item := fixture.pushNode(t, owner.Principal, owner.Principal.UserID, database.KindItem, &root.ID)
	head, err := fixture.store.FeedHead(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	for _, stream := range []*sseStream{ownerStream, viewerStream} {
		received := stream.nextChangeUpTo(t, head)
		data := received.decode(t)
		if data["collection"] != photos || data["seq"] != float64(head) {
			t.Fatalf("change for %s: %+v", item.ID, received)
		}
	}
	viewerWithoutScope.expectNoChange(t)
	strangerStream.expectNoChange(t)
}

// nextChangeUpTo reads changes until one carries the sequence.
func (stream *sseStream) nextChangeUpTo(t *testing.T, seq int64) event {
	t.Helper()
	for {
		received := stream.nextChange(t)
		if received.decode(t)["seq"] == float64(seq) {
			return received
		}
	}
}

func (stream *sseStream) expectNoChange(t *testing.T) {
	t.Helper()
	for {
		select {
		case received, open := <-stream.events:
			if open && received.name == "change" {
				t.Fatalf("unexpected change %+v", received)
			}
			if !open {
				return
			}
		case <-timeAfterQuiet():
			return
		}
	}
}

func TestRevokedPrincipalHearsOfTheRevoke(t *testing.T) {
	fixture := newLiveFixture(t)
	owner := dbtest.CreateAccount(t, fixture.store)
	viewer := dbtest.CreateAccount(t, fixture.store)
	root := fixture.pushNode(t, owner.Principal, owner.Principal.UserID, database.KindRoot, nil)
	owner.Grant(t, fixture.store, root.ID, dbtest.WriteGrant("user", owner.Principal.UserID, 1))
	owner.Grant(t, fixture.store, root.ID, dbtest.ReadGrant("user", viewer.Principal.UserID, 1))
	viewerStream := fixture.open(t, clientOptions{userID: viewer.Principal.UserID, scopes: photos + ":read"})

	owner.Revoke(t, fixture.store, root.ID, "user", viewer.Principal.UserID)

	received := viewerStream.nextChange(t)
	if received.decode(t)["collection"] != photos {
		t.Fatalf("revoke change: %+v", received)
	}
}

func TestReconnectWithAnOldEventIDLearnsOfMissedChangesFromTheDatabase(t *testing.T) {
	fixture := newLiveFixture(t)
	owner := dbtest.CreateAccount(t, fixture.store)
	stranger := dbtest.CreateAccount(t, fixture.store)
	root := fixture.pushNode(t, owner.Principal, owner.Principal.UserID, database.KindRoot, nil)
	owner.Grant(t, fixture.store, root.ID, dbtest.WriteGrant("user", owner.Principal.UserID, 1))
	head, err := fixture.store.FeedHead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fixture.pushNode(t, owner.Principal, owner.Principal.UserID, database.KindItem, &root.ID)

	ownerStream := fixture.open(t, clientOptions{userID: owner.Principal.UserID, scopes: photos + ":read", lastEventID: itoa(head)})
	strangerStream := fixture.open(t, clientOptions{userID: stranger.Principal.UserID, scopes: photos + ":read", lastEventID: itoa(head)})

	missed := ownerStream.nextResync(t, "missed")
	if missed.id == "" {
		t.Fatalf("a missed resync carries the head: %+v", missed)
	}
	strangerStream.expectNoResync(t, "missed")
}
