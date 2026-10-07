package nodes_test

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/accesslog"
	"github.com/neoworks/auth/handlers/handlertest"
	"github.com/neoworks/auth/handlers/nodes"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
)

func newRouter(t *testing.T) (*handlertest.Router, *database.SurrealStore) {
	store := dbtest.New(t)
	handler := nodes.NewHandler(store)
	router := handlertest.NewAuthenticated(func(router chi.Router) {
		handler.RegisterAuthenticated(router)
		handler.RegisterPublic(router)
	})
	return router, store
}

// wireNode builds a pushed node as the JSON object clients send.
func wireNode(author access.Principal, collection, kind string, parentID *string) map[string]any {
	node := map[string]any{
		"id": uuid.NewString(), "parentId": parentID, "ownerId": author.UserID,
		"collection": collection, "kind": kind, "epoch": 1,
		"content":    "",
		"blob":       nil,
		"deleted":    false,
		"baseSeq":    0,
		"authorType": author.Type(), "authorId": author.ID(),
		"certId": nil, "signature": "c2ln",
	}
	if kind == "root" {
		node["wrappedKey"] = nil
	} else {
		node["wrappedKey"] = "d3JhcHBlZA"
		node["content"] = dbtest.Content("ct")
	}
	return node
}

type pushResponse struct {
	Results []struct {
		ID      string         `json:"id"`
		Status  string         `json:"status"`
		Seq     int64          `json:"seq"`
		Current map[string]any `json:"current"`
	} `json:"results"`
}

func push(t *testing.T, router *handlertest.Router, author access.Principal, nodes ...map[string]any) pushResponse {
	t.Helper()
	response := router.Do(t, author, "POST", "/api/v1/nodes/push", map[string]any{"nodes": nodes}, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("push: %d %s", response.Code, response.Body.String())
	}
	var parsed pushResponse
	handlertest.Decode(t, response, &parsed)
	return parsed
}

// bootstrapRoot pushes a root for the owner and posts the owner's own grant as
// entry 0 of its log.
func bootstrapRoot(t *testing.T, router *handlertest.Router, store *database.SurrealStore, account *dbtest.Account) map[string]any {
	t.Helper()
	owner := account.Principal
	dbtest.PublishNodeSchemas(t, store)
	root := wireNode(owner, "@neoworks/calendar", "root", nil)
	push(t, router, owner, root)
	request := account.GrantRequest(t, store, root["id"].(string), dbtest.WriteGrant("user", owner.UserID, 1))
	response := router.Do(t, owner, "POST", "/api/v1/nodes/"+root["id"].(string)+"/grants", request, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("bootstrap grant: %d %s", response.Code, response.Body.String())
	}
	return root
}

func TestPushReportsPerNodeStatuses(t *testing.T) {
	router, store := newRouter(t)
	ownerAccount := dbtest.CreateAccount(t, store, "@neoworks/calendar:read", "@neoworks/calendar:write")
	owner := ownerAccount.Principal
	strangerAccount := dbtest.CreateAccount(t, store, "@neoworks/calendar:read", "@neoworks/calendar:write")
	stranger := strangerAccount.Principal
	root := bootstrapRoot(t, router, store, ownerAccount)
	rootID := root["id"].(string)

	accepted := wireNode(owner, "@neoworks/calendar", "item", &rootID)
	rejected := wireNode(stranger, "@neoworks/calendar", "item", &rootID)
	rejected["ownerId"] = owner.UserID

	first := push(t, router, owner, accepted)
	if first.Results[0].Status != "ok" || first.Results[0].Seq == 0 {
		t.Fatalf("accepted push: %+v", first.Results[0])
	}
	if status := push(t, router, stranger, rejected).Results[0].Status; status != "forbidden" {
		t.Fatalf("stranger push: got %s want forbidden", status)
	}

	stale := push(t, router, owner, accepted).Results[0]
	if stale.Status != "conflict" || stale.Current == nil || stale.Current["id"] != accepted["id"] {
		t.Fatalf("stale push should conflict with the current node: %+v", stale)
	}
}

func TestPushRejectsAMalformedNodeWithoutWritingTheBatch(t *testing.T) {
	router, store := newRouter(t)
	ownerAccount := dbtest.CreateAccount(t, store, "@neoworks/calendar:read", "@neoworks/calendar:write")
	owner := ownerAccount.Principal
	root := bootstrapRoot(t, router, store, ownerAccount)
	rootID := root["id"].(string)

	good := wireNode(owner, "@neoworks/calendar", "item", &rootID)
	bad := wireNode(owner, "@neoworks/calendar", "item", &rootID)
	bad["signature"] = ""
	response := router.Do(t, owner, "POST", "/api/v1/nodes/push", map[string]any{"nodes": []any{good, bad}}, nil)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("malformed batch: got %d want 400", response.Code)
	}

	var page database.PullPage
	handlertest.Decode(t, router.Do(t, owner, "GET", "/api/v1/nodes/pull", nil, nil), &page)
	for _, node := range page.Nodes {
		if node.ID == good["id"] {
			t.Fatal("the valid node of a rejected batch must not be written")
		}
	}
}

func TestPullAnswers410WithThePurgeHorizon(t *testing.T) {
	router, store := newRouter(t)
	ownerAccount := dbtest.CreateAccount(t, store, "@neoworks/calendar:read", "@neoworks/calendar:write")
	owner := ownerAccount.Principal
	root := bootstrapRoot(t, router, store, ownerAccount)
	rootID := root["id"].(string)

	doomed := wireNode(owner, "@neoworks/calendar", "item", &rootID)
	seq := push(t, router, owner, doomed).Results[0].Seq
	doomed["baseSeq"] = seq
	doomed["deleted"] = true
	doomed["content"] = ""
	tombstoneSeq := push(t, router, owner, doomed).Results[0].Seq
	if _, err := store.PurgeTombstones(t.Context(), -60_000_000_000); err != nil {
		t.Fatalf("purge: %v", err)
	}

	stale := router.Do(t, owner, "GET", "/api/v1/nodes/pull?cursor=1", nil, nil)
	if stale.Code != http.StatusGone {
		t.Fatalf("stale cursor: got %d want 410", stale.Code)
	}
	var body struct {
		PurgeHorizon int64 `json:"purgeHorizon"`
	}
	handlertest.Decode(t, stale, &body)
	if body.PurgeHorizon != tombstoneSeq {
		t.Fatalf("purgeHorizon %d want %d", body.PurgeHorizon, tombstoneSeq)
	}
	if full := router.Do(t, owner, "GET", "/api/v1/nodes/pull?cursor=0", nil, nil); full.Code != http.StatusOK {
		t.Fatalf("full resync: got %d want 200", full.Code)
	}
}

func TestGrantEndpointsEnforceTheOwnerRules(t *testing.T) {
	router, store := newRouter(t)
	ownerAccount := dbtest.CreateAccount(t, store, "@neoworks/calendar:read", "@neoworks/calendar:write")
	owner := ownerAccount.Principal
	writerAccount := dbtest.CreateAccount(t, store, "@neoworks/calendar:read", "@neoworks/calendar:write")
	writer := writerAccount.Principal
	thirdAccount := dbtest.CreateAccount(t, store, "@neoworks/calendar:read", "@neoworks/calendar:write")
	third := thirdAccount.Principal
	root := bootstrapRoot(t, router, store, ownerAccount)
	rootID := root["id"].(string)
	grantsPath := "/api/v1/nodes/" + rootID + "/grants"

	ownerGrant := ownerAccount.GrantRequest(t, store, rootID, dbtest.WriteGrant("user", writer.UserID, 1))
	if response := router.Do(t, owner, "POST", grantsPath, ownerGrant, nil); response.Code != http.StatusOK {
		t.Fatalf("owner grants write: %d %s", response.Code, response.Body.String())
	}
	var granted database.GrantResult
	handlertest.Decode(t, router.Do(t, owner, "POST", grantsPath,
		ownerAccount.GrantRequest(t, store, rootID, dbtest.ReadGrant("user", third.UserID, 1)), nil), &granted)
	if granted.Grant.LogIndex != 2 || granted.Entry.EntryHash == "" {
		t.Fatalf("the response should carry logIndex and entryHash: %+v", granted)
	}

	if response := router.Do(t, writer, "POST", grantsPath,
		writerAccount.GrantRequest(t, store, rootID, dbtest.ReadGrant("user", third.UserID, 1)), nil); response.Code != http.StatusForbidden {
		t.Fatalf("a writer sharing with another user: got %d want 403", response.Code)
	}
	if response := router.Do(t, third, "POST", grantsPath,
		thirdAccount.GrantRequest(t, store, rootID, dbtest.ReadGrant("user", third.UserID, 1)), nil); response.Code != http.StatusForbidden {
		t.Fatalf("a reader granting: got %d want 403", response.Code)
	}
	stale := dbtest.ReadGrant("user", third.UserID, 9)
	if response := router.Do(t, owner, "POST", grantsPath, ownerAccount.GrantRequest(t, store, rootID, stale), nil); response.Code != http.StatusConflict {
		t.Fatalf("stale epoch grant: got %d want 409", response.Code)
	}

	revokePath := grantsPath + "/revoke"
	revoke := map[string]any{"entry": writerAccount.RevokeEntry(t, store, rootID, "user", owner.UserID)}
	if response := router.Do(t, writer, "POST", revokePath, revoke, nil); response.Code != http.StatusForbidden {
		t.Fatalf("a writer revoking the owner: got %d want 403", response.Code)
	}
	revoke = map[string]any{"entry": ownerAccount.RevokeEntry(t, store, rootID, "user", writer.UserID)}
	if response := router.Do(t, owner, "POST", revokePath, revoke, nil); response.Code != http.StatusOK {
		t.Fatalf("owner revokes: got %d want 200", response.Code)
	}
}

func TestStaleLogHeadAnswers409WithTheHead(t *testing.T) {
	router, store := newRouter(t)
	ownerAccount := dbtest.CreateAccount(t, store, "@neoworks/calendar:read", "@neoworks/calendar:write")
	other := dbtest.CreateAccount(t, store, "@neoworks/calendar:read", "@neoworks/calendar:write")
	root := bootstrapRoot(t, router, store, ownerAccount)
	rootID := root["id"].(string)

	stale := ownerAccount.GrantRequestAt(t, rootID, dbtest.ReadGrant("user", other.Principal.UserID, 1), 0, accesslog.GenesisPrevHash)
	response := router.Do(t, ownerAccount.Principal, "POST", "/api/v1/nodes/"+rootID+"/grants", stale, nil)
	if response.Code != http.StatusConflict {
		t.Fatalf("an entry that does not extend the head: got %d want 409", response.Code)
	}
	var body struct {
		Error string `json:"error"`
		Head  struct {
			Index     int64  `json:"index"`
			EntryHash string `json:"entryHash"`
		} `json:"head"`
	}
	handlertest.Decode(t, response, &body)
	if body.Error != "log_head_moved" || body.Head.Index != 0 || body.Head.EntryHash == "" {
		t.Fatalf("409 body: %+v", body)
	}
}

func TestAccessLogEndpointReturnsTheChainToReaders(t *testing.T) {
	router, store := newRouter(t)
	ownerAccount := dbtest.CreateAccount(t, store, "@neoworks/calendar:read", "@neoworks/calendar:write")
	stranger := dbtest.CreateAccount(t, store, "@neoworks/calendar:read", "@neoworks/calendar:write")
	root := bootstrapRoot(t, router, store, ownerAccount)
	path := "/api/v1/nodes/" + root["id"].(string) + "/access-log"

	var log struct {
		Entries []accesslog.Entry `json:"entries"`
	}
	handlertest.Decode(t, router.Do(t, ownerAccount.Principal, "GET", path, nil, nil), &log)
	if len(log.Entries) != 1 || log.Entries[0].Index != 0 || log.Entries[0].EntryHash == "" {
		t.Fatalf("log: %+v", log)
	}
	if response := router.Do(t, stranger.Principal, "GET", path, nil, nil); response.Code != http.StatusNotFound {
		t.Fatalf("a stranger reading the log: got %d want 404", response.Code)
	}
	if response := router.Do(t, ownerAccount.Principal, "DELETE", "/api/v1/nodes/x/grants/user/y", nil, nil); response.Code != http.StatusMethodNotAllowed && response.Code != http.StatusNotFound {
		t.Fatalf("the DELETE grant route is gone: got %d", response.Code)
	}
}

func TestLinkPullNeedsNoPrincipal(t *testing.T) {
	router, store := newRouter(t)
	ownerAccount := dbtest.CreateAccount(t, store, "@neoworks/calendar:read", "@neoworks/calendar:write")
	owner := ownerAccount.Principal
	root := bootstrapRoot(t, router, store, ownerAccount)

	created := router.Do(t, owner, "POST", "/api/v1/links", map[string]any{"nodeId": root["id"]}, nil)
	if created.Code != http.StatusOK {
		t.Fatalf("create link: %d %s", created.Code, created.Body.String())
	}
	var link database.Link
	handlertest.Decode(t, created, &link)

	anonymous := access.Principal{}
	pulled := router.Do(t, anonymous, "GET", "/api/v1/links/"+link.ID+"/pull", nil, nil)
	if pulled.Code != http.StatusOK {
		t.Fatalf("anonymous link pull: %d %s", pulled.Code, pulled.Body.String())
	}
	if missing := router.Do(t, anonymous, "GET", "/api/v1/links/"+uuid.NewString()+"/pull", nil, nil); missing.Code != http.StatusNotFound {
		t.Fatalf("unknown link: got %d want 404", missing.Code)
	}
}
