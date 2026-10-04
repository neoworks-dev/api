package nodes_test

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/neoworks/auth/access"
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
		"content":    []map[string]any{{"facet": 0, "ciphertext": "Y3Q"}},
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

func bootstrapRoot(t *testing.T, router *handlertest.Router, owner access.Principal) map[string]any {
	t.Helper()
	root := wireNode(owner, "calendar", "root", nil)
	push(t, router, owner, root)
	grant := map[string]any{
		"principalType": "user", "principalId": owner.UserID, "role": "admin",
		"facets": nil, "epoch": 1, "wrappedKeys": "c2VhbGVk", "signature": "c2ln",
	}
	response := router.Do(t, owner, "POST", "/api/v1/nodes/"+root["id"].(string)+"/grants", grant, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("bootstrap grant: %d %s", response.Code, response.Body.String())
	}
	return root
}

func TestPushReportsPerNodeStatuses(t *testing.T) {
	router, store := newRouter(t)
	owner := handlertest.CreateUser(t, store, "calendar:read", "calendar:write")
	stranger := handlertest.CreateUser(t, store, "calendar:read", "calendar:write")
	root := bootstrapRoot(t, router, owner)
	rootID := root["id"].(string)

	accepted := wireNode(owner, "calendar", "item", &rootID)
	rejected := wireNode(stranger, "calendar", "item", &rootID)
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
	owner := handlertest.CreateUser(t, store, "calendar:read", "calendar:write")
	root := bootstrapRoot(t, router, owner)
	rootID := root["id"].(string)

	good := wireNode(owner, "calendar", "item", &rootID)
	bad := wireNode(owner, "calendar", "item", &rootID)
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
	owner := handlertest.CreateUser(t, store, "calendar:read", "calendar:write")
	root := bootstrapRoot(t, router, owner)
	rootID := root["id"].(string)

	doomed := wireNode(owner, "calendar", "item", &rootID)
	seq := push(t, router, owner, doomed).Results[0].Seq
	doomed["baseSeq"] = seq
	doomed["deleted"] = true
	doomed["content"] = []map[string]any{}
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

func TestGrantEndpointsEnforceAdmin(t *testing.T) {
	router, store := newRouter(t)
	owner := handlertest.CreateUser(t, store, "calendar:read", "calendar:write")
	writer := handlertest.CreateUser(t, store, "calendar:read", "calendar:write")
	third := handlertest.CreateUser(t, store, "calendar:read", "calendar:write")
	root := bootstrapRoot(t, router, owner)
	rootPath := "/api/v1/nodes/" + root["id"].(string) + "/grants"

	grantTo := func(user access.Principal, role string) map[string]any {
		return map[string]any{
			"principalType": "user", "principalId": user.UserID, "role": role,
			"facets": nil, "epoch": 1, "wrappedKeys": "c2VhbGVk", "signature": "c2ln",
		}
	}
	if response := router.Do(t, owner, "POST", rootPath, grantTo(writer, "write"), nil); response.Code != http.StatusOK {
		t.Fatalf("owner grants write: %d %s", response.Code, response.Body.String())
	}
	if response := router.Do(t, writer, "POST", rootPath, grantTo(third, "read"), nil); response.Code != http.StatusForbidden {
		t.Fatalf("writer grants: got %d want 403", response.Code)
	}
	if response := router.Do(t, third, "POST", rootPath, grantTo(third, "admin"), nil); response.Code != http.StatusNotFound {
		t.Fatalf("outsider grants: got %d want 404", response.Code)
	}
	stale := grantTo(third, "read")
	stale["epoch"] = 9
	if response := router.Do(t, owner, "POST", rootPath, stale, nil); response.Code != http.StatusConflict {
		t.Fatalf("stale epoch grant: got %d want 409", response.Code)
	}

	revokePath := rootPath + "/user/" + writer.UserID
	if response := router.Do(t, writer, "DELETE", revokePath, nil, nil); response.Code != http.StatusForbidden {
		t.Fatalf("writer revokes: got %d want 403", response.Code)
	}
	if response := router.Do(t, owner, "DELETE", revokePath, nil, nil); response.Code != http.StatusNoContent {
		t.Fatalf("owner revokes: got %d want 204", response.Code)
	}
}

func TestLinkPullNeedsNoPrincipal(t *testing.T) {
	router, store := newRouter(t)
	owner := handlertest.CreateUser(t, store, "calendar:read", "calendar:write")
	root := bootstrapRoot(t, router, owner)

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
