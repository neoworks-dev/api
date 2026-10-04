package blobs_test

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/handlers/blobs"
	"github.com/neoworks/auth/handlers/handlertest"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
)

type fakePresigner struct{}

func (fakePresigner) PresignPut(_ context.Context, key string, _ time.Duration) (string, error) {
	return "https://s3.test/put/" + key, nil
}

func (fakePresigner) PresignGet(_ context.Context, key string, _ time.Duration) (string, error) {
	return "https://s3.test/get/" + key, nil
}

type fixture struct {
	t       *testing.T
	router  *handlertest.Router
	store   *database.SurrealStore
	account *dbtest.Account
	owner   access.Principal
	nodeID  string
	object  string
}

// newFixture stores a files node whose blob has 3 chunks and 100 declared bytes.
func newFixture(t *testing.T, quotaBytes int64) *fixture {
	store := dbtest.New(t)
	handler := blobs.NewHandler(store, fakePresigner{}, quotaBytes)
	router := handlertest.NewAuthenticated(func(router chi.Router) {
		handler.RegisterAuthenticated(router)
		handler.RegisterPublic(router)
	})
	account := dbtest.CreateAccount(t, store, "files:read", "files:write")
	fx := &fixture{t: t, router: router, store: store, account: account, owner: account.Principal, object: uuid.NewString()}
	fx.nodeID = fx.storeFile(fx.owner, fx.object)
	return fx
}

func (fx *fixture) storeFile(owner access.Principal, objectID string) string {
	root := database.Node{
		ID: uuid.NewString(), OwnerID: owner.UserID, Collection: "files", Kind: database.KindRoot, Epoch: 1,
		Content: []database.FacetContent{{Facet: 0, Ciphertext: "ct"}}, AuthorType: "user", AuthorID: owner.UserID, Signature: "sig",
	}
	fx.push(owner, root)
	fx.account.Grant(fx.t, fx.store, root.ID, dbtest.WriteGrant("user", owner.UserID, 1))
	wrapped := "wrapped"
	file := root
	file.ID, file.Kind, file.ParentID, file.WrappedKey = uuid.NewString(), database.KindItem, &root.ID, &wrapped
	file.Blob = []byte(`{"objectId":"` + objectID + `","chunks":3,"size":100}`)
	fx.push(owner, file)
	return file.ID
}

func (fx *fixture) push(author access.Principal, node database.Node) {
	validated, err := database.ValidateNodeInput(node, author)
	if err != nil {
		fx.t.Fatalf("validate: %v", err)
	}
	outcome, err := fx.store.PushNode(context.Background(), author, validated)
	if err != nil || outcome.Status != database.StatusOK {
		fx.t.Fatalf("push: %+v %v", outcome, err)
	}
}

func (fx *fixture) presign(principal access.Principal, op string, chunks ...int) (int, []map[string]any) {
	body := map[string]any{"nodeId": fx.nodeID, "objectId": fx.object, "op": op, "chunks": chunks}
	response := fx.router.Do(fx.t, principal, "POST", "/api/v1/blobs/presign", body, nil)
	var parsed struct {
		URLs []map[string]any `json:"urls"`
	}
	if response.Code == http.StatusOK {
		handlertest.Decode(fx.t, response, &parsed)
	}
	return response.Code, parsed.URLs
}

func TestPresignUsesObjectIDAndChunkIndexAsKey(t *testing.T) {
	fx := newFixture(t, 1000)
	code, urls := fx.presign(fx.owner, "put", 0, 2)
	if code != http.StatusOK || len(urls) != 2 {
		t.Fatalf("presign put: %d %v", code, urls)
	}
	for position, index := range []int{0, 2} {
		want := "https://s3.test/put/" + fx.object + "/" + strconv.Itoa(index)
		if urls[position]["url"] != want || int(urls[position]["index"].(float64)) != index {
			t.Fatalf("url %d: %v want %s", position, urls[position], want)
		}
	}
	code, urls = fx.presign(fx.owner, "get", 1)
	if code != http.StatusOK || urls[0]["url"] != "https://s3.test/get/"+fx.object+"/1" {
		t.Fatalf("presign get: %d %v", code, urls)
	}
}

func TestPresignPutIsRefusedOverQuotaButGetStillWorks(t *testing.T) {
	fx := newFixture(t, 99)
	if code, _ := fx.presign(fx.owner, "put", 0); code != http.StatusForbidden {
		t.Fatalf("put over quota: got %d want 403", code)
	}
	if code, _ := fx.presign(fx.owner, "get", 0); code != http.StatusOK {
		t.Fatalf("get over quota: got %d want 200", code)
	}
}

func TestPresignPutAtExactlyTheQuotaIsAllowed(t *testing.T) {
	fx := newFixture(t, 100)
	if code, _ := fx.presign(fx.owner, "put", 0); code != http.StatusOK {
		t.Fatalf("put at quota: got %d want 200", code)
	}
}

func TestPresignValidatesChunksAndObject(t *testing.T) {
	fx := newFixture(t, 1000)
	if code, _ := fx.presign(fx.owner, "put", 3); code != http.StatusBadRequest {
		t.Fatalf("chunk past the end: got %d want 400", code)
	}
	if code, _ := fx.presign(fx.owner, "put", 1, 1); code != http.StatusBadRequest {
		t.Fatalf("duplicate chunk: got %d want 400", code)
	}
	if code, _ := fx.presign(fx.owner, "put"); code != http.StatusBadRequest {
		t.Fatalf("no chunks: got %d want 400", code)
	}
	if code, _ := fx.presign(fx.owner, "delete", 0); code != http.StatusBadRequest {
		t.Fatalf("bad op: got %d want 400", code)
	}
	body := map[string]any{"nodeId": fx.nodeID, "objectId": uuid.NewString(), "op": "get", "chunks": []int{0}}
	if response := fx.router.Do(t, fx.owner, "POST", "/api/v1/blobs/presign", body, nil); response.Code != http.StatusNotFound {
		t.Fatalf("object not in the node's blob: got %d want 404", response.Code)
	}
}

func TestPresignChecksNodeAccessAndScope(t *testing.T) {
	fx := newFixture(t, 1000)
	strangerAccount := dbtest.CreateAccount(t, fx.store, "files:read", "files:write")
	stranger := strangerAccount.Principal
	if code, _ := fx.presign(stranger, "get", 0); code != http.StatusNotFound {
		t.Fatalf("stranger get: got %d want 404", code)
	}

	node, err := fx.store.GetNodeForPrincipal(context.Background(), fx.owner, fx.nodeID)
	if err != nil || node.ParentID == nil {
		t.Fatalf("load node: %v", err)
	}
	fx.account.Grant(t, fx.store, *node.ParentID, dbtest.ReadGrant("user", stranger.UserID, 1))
	if code, _ := fx.presign(stranger, "get", 0); code != http.StatusOK {
		t.Fatalf("reader get: got %d want 200", code)
	}
	if code, _ := fx.presign(stranger, "put", 0); code != http.StatusForbidden {
		t.Fatalf("reader put: got %d want 403", code)
	}

	readScoped := access.Principal{UserID: fx.owner.UserID, Scopes: []string{"files:read"}}
	if code, _ := fx.presign(readScoped, "put", 0); code != http.StatusForbidden {
		t.Fatalf("read-scoped owner put: got %d want 403", code)
	}
	wrongCollection := access.Principal{UserID: fx.owner.UserID, Scopes: []string{"photos:write"}}
	if code, _ := fx.presign(wrongCollection, "get", 0); code != http.StatusNotFound {
		t.Fatalf("photos-scoped get of a file: got %d want 404", code)
	}
}

func TestLinkPresignIsDownloadOnlyWithinTheSharedSubtree(t *testing.T) {
	fx := newFixture(t, 1000)
	node, _ := fx.store.GetNodeForPrincipal(context.Background(), fx.owner, fx.nodeID)
	link, err := fx.store.CreateLink(context.Background(), fx.owner, *node.ParentID)
	if err != nil {
		t.Fatalf("create link: %v", err)
	}
	body := map[string]any{"nodeId": fx.nodeID, "objectId": fx.object, "op": "put", "chunks": []int{0}}
	response := fx.router.Do(t, access.Principal{}, "POST", "/api/v1/links/"+link.ID+"/presign", body, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("link presign: %d %s", response.Code, response.Body.String())
	}
	var parsed struct {
		URLs []map[string]any `json:"urls"`
	}
	handlertest.Decode(t, response, &parsed)
	if parsed.URLs[0]["url"] != "https://s3.test/get/"+fx.object+"/0" {
		t.Fatalf("a link must only ever get download URLs: %v", parsed.URLs)
	}

	other := fx.storeFile(fx.owner, uuid.NewString())
	body["nodeId"] = other
	if response := fx.router.Do(t, access.Principal{}, "POST", "/api/v1/links/"+link.ID+"/presign", body, nil); response.Code == http.StatusOK {
		t.Fatal("a node outside the link's subtree must not be presigned")
	}
}
