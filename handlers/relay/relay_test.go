package relay_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/websocket"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/handlers/relay"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/ratelimit"
	"github.com/neoworks/auth/storage/database"
	"github.com/redis/go-redis/v9"
)

type registeredClients map[string]bool

func (known registeredClients) GetClient(_ context.Context, clientID string) (*oauth.Client, error) {
	if !known[clientID] {
		return nil, database.ErrNotFound
	}
	return &oauth.Client{}, nil
}

type noStandings struct{}

func (noStandings) GetClientStanding(context.Context, string) (*database.ClientStanding, error) {
	return nil, database.ErrNotFound
}

// signInAsTokenParts treats the token "userID@clientID" as an already verified
// access token, so the tests need no signing keys.
func signInAsTokenParts(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		userID, clientID, _ := strings.Cut(token, "@")
		principal := access.Principal{UserID: userID, ClientID: clientID}
		next.ServeHTTP(w, r.WithContext(middleware.ContextWithPrincipal(r.Context(), principal)))
	})
}

type instance struct {
	server  *httptest.Server
	handler *relay.Handler
}

func newInstance(t *testing.T, redisAddress string, limits relay.Limits) *instance {
	t.Helper()
	redisClient := redis.NewClient(&redis.Options{Addr: redisAddress})
	counter := ratelimit.NewRedisCounter(redisClient)
	limiter := ratelimit.New(counter, counter, noStandings{})
	hub := relay.NewHub(redisClient)
	handler := relay.NewHandler(hub, registeredClients{"appA": true, "appB": true}, limiter).WithLimits(limits)
	signedIn := signInAsTokenParts(limiter.Authenticated(handler.SignedIn()))
	anonymous := limiter.ByIP(ratelimit.BucketPublic)(handler.Anonymous())
	server := httptest.NewServer(relay.ChooseByToken(signedIn, anonymous))
	t.Cleanup(func() {
		server.Close()
		hub.Close()
		_ = redisClient.Close()
	})
	return &instance{server: server, handler: handler}
}

func (inst *instance) websocketURL(query string) string {
	return "ws" + strings.TrimPrefix(inst.server.URL, "http") + "/api/v1/relay" + query
}

func (inst *instance) dialAnonymous(t *testing.T, clientID string) *websocket.Conn {
	t.Helper()
	socket, response, err := websocket.DefaultDialer.Dial(inst.websocketURL("?client_id="+clientID), nil)
	if err != nil {
		t.Fatalf("dial anonymous %s: %v (response %v)", clientID, err, response)
	}
	t.Cleanup(func() { _ = socket.Close() })
	return socket
}

func (inst *instance) dialSignedIn(t *testing.T, userID string, clientID string) *websocket.Conn {
	t.Helper()
	dialer := websocket.Dialer{Subprotocols: []string{relay.Subprotocol, "bearer." + userID + "@" + clientID}}
	socket, response, err := dialer.Dial(inst.websocketURL(""), nil)
	if err != nil {
		t.Fatalf("dial signed in %s: %v (response %v)", userID, err, response)
	}
	t.Cleanup(func() { _ = socket.Close() })
	return socket
}

type frame map[string]any

func send(t *testing.T, socket *websocket.Conn, value frame) {
	t.Helper()
	if err := socket.WriteJSON(value); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

func receive(t *testing.T, socket *websocket.Conn) frame {
	t.Helper()
	_ = socket.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, raw, err := socket.ReadMessage()
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	var received frame
	if err := json.Unmarshal(raw, &received); err != nil {
		t.Fatalf("decode frame %s: %v", raw, err)
	}
	return received
}

func expectSilence(t *testing.T, socket *websocket.Conn) {
	t.Helper()
	_ = socket.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, raw, err := socket.ReadMessage()
	if err == nil {
		t.Fatalf("expected no frame, received %s", raw)
	}
}

func subscribe(t *testing.T, socket *websocket.Conn, topic string) {
	t.Helper()
	send(t, socket, frame{"type": "subscribe", "topic": topic})
	acknowledged := receive(t, socket)
	if acknowledged["type"] != "subscribed" || acknowledged["topic"] != topic {
		t.Fatalf("subscribe %q answered with %v", topic, acknowledged)
	}
}

func expectMessage(t *testing.T, socket *websocket.Conn, topic string, data string) {
	t.Helper()
	received := receive(t, socket)
	if received["type"] != "message" || received["topic"] != topic || received["data"] != data {
		t.Fatalf("expected message %q on %q, received %v", data, topic, received)
	}
}

func expectError(t *testing.T, socket *websocket.Conn, code string) frame {
	t.Helper()
	received := receive(t, socket)
	if received["type"] != "error" || received["code"] != code {
		t.Fatalf("expected error %q, received %v", code, received)
	}
	return received
}

func TestPublishReachesEverySubscriberOfTheTopic(t *testing.T) {
	redisServer := miniredis.RunT(t)
	inst := newInstance(t, redisServer.Addr(), relay.DefaultLimits)
	publisher := inst.dialAnonymous(t, "appA")
	subscriber := inst.dialAnonymous(t, "appA")
	otherSubscriber := inst.dialAnonymous(t, "appA")
	subscribe(t, subscriber, "room-1")
	subscribe(t, otherSubscriber, "room-1")

	send(t, publisher, frame{"type": "publish", "topic": "room-1", "data": "sealed-bytes"})

	expectMessage(t, subscriber, "room-1", "sealed-bytes")
	expectMessage(t, otherSubscriber, "room-1", "sealed-bytes")
	expectSilence(t, publisher)
}

func TestSignedInAndAnonymousConnectionsOfOneClientMeet(t *testing.T) {
	inst := newInstance(t, miniredis.RunT(t).Addr(), relay.DefaultLimits)
	signedIn := inst.dialSignedIn(t, "user-1", "appA")
	anonymous := inst.dialAnonymous(t, "appA")
	subscribe(t, anonymous, "room-1")

	send(t, signedIn, frame{"type": "publish", "topic": "room-1", "data": "hello"})

	expectMessage(t, anonymous, "room-1", "hello")
}

func TestClientsNeverSeeEachOthersTopics(t *testing.T) {
	inst := newInstance(t, miniredis.RunT(t).Addr(), relay.DefaultLimits)
	listenerOfA := inst.dialAnonymous(t, "appA")
	listenerOfB := inst.dialSignedIn(t, "user-1", "appB")
	publisherOfA := inst.dialAnonymous(t, "appA")
	subscribe(t, listenerOfA, "shared-name")
	subscribe(t, listenerOfB, "shared-name")

	send(t, publisherOfA, frame{"type": "publish", "topic": "shared-name", "data": "for-a"})

	expectMessage(t, listenerOfA, "shared-name", "for-a")
	expectSilence(t, listenerOfB)
}

func TestClientIDsContainingSeparatorsDoNotCollide(t *testing.T) {
	inst := newInstance(t, miniredis.RunT(t).Addr(), relay.DefaultLimits)
	listener := inst.dialSignedIn(t, "user-1", "a:b")
	publisher := inst.dialSignedIn(t, "user-2", "a")
	subscribe(t, listener, "c")

	send(t, publisher, frame{"type": "publish", "topic": "b:c", "data": "x"})

	expectSilence(t, listener)
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	inst := newInstance(t, miniredis.RunT(t).Addr(), relay.DefaultLimits)
	subscriber := inst.dialAnonymous(t, "appA")
	publisher := inst.dialAnonymous(t, "appA")
	subscribe(t, subscriber, "room-1")
	send(t, subscriber, frame{"type": "unsubscribe", "topic": "room-1"})
	if answered := receive(t, subscriber); answered["type"] != "unsubscribed" {
		t.Fatalf("unsubscribe answered with %v", answered)
	}

	send(t, publisher, frame{"type": "publish", "topic": "room-1", "data": "late"})

	expectSilence(t, subscriber)
}

func TestMessagesCrossInstancesThroughRedis(t *testing.T) {
	redisServer := miniredis.RunT(t)
	firstInstance := newInstance(t, redisServer.Addr(), relay.DefaultLimits)
	secondInstance := newInstance(t, redisServer.Addr(), relay.DefaultLimits)
	subscriber := firstInstance.dialAnonymous(t, "appA")
	publisher := secondInstance.dialSignedIn(t, "user-1", "appA")
	subscribe(t, subscriber, "room-1")

	send(t, publisher, frame{"type": "publish", "topic": "room-1", "data": "across"})

	expectMessage(t, subscriber, "room-1", "across")
}

func TestAnonymousConnectionNeedsARegisteredClient(t *testing.T) {
	inst := newInstance(t, miniredis.RunT(t).Addr(), relay.DefaultLimits)
	cases := map[string]int{"?client_id=nobody": http.StatusForbidden, "": http.StatusBadRequest}
	for query, wantStatus := range cases {
		_, response, err := websocket.DefaultDialer.Dial(inst.websocketURL(query), nil)
		if err == nil || response == nil || response.StatusCode != wantStatus {
			t.Fatalf("query %q: want status %d, got %v (%v)", query, wantStatus, response, err)
		}
	}
}

func TestAnonymousFramesAreLimitedPerIP(t *testing.T) {
	inst := newInstance(t, miniredis.RunT(t).Addr(), relay.DefaultLimits)
	socket := inst.dialAnonymous(t, "appA")
	limit := ratelimit.DefaultLimits[ratelimit.BucketRelay].PerIP

	exhaustFrames(t, socket, limit)
	send(t, socket, frame{"type": "unsubscribe", "topic": "t"})

	limited := expectError(t, socket, "rate_limited")
	if limited["retryAfter"] == nil || limited["topic"] != "t" {
		t.Fatalf("rate limit error without retryAfter: %v", limited)
	}
}

func TestSignedInFramesAreLimitedPerUserAndMoreGenerouslyThanAnonymous(t *testing.T) {
	inst := newInstance(t, miniredis.RunT(t).Addr(), relay.DefaultLimits)
	limits := ratelimit.DefaultLimits[ratelimit.BucketRelay]
	if limits.PerUserClient <= limits.PerIP {
		t.Fatalf("signed-in limit %d must exceed the anonymous limit %d", limits.PerUserClient, limits.PerIP)
	}
	first := inst.dialSignedIn(t, "user-1", "appA")
	second := inst.dialSignedIn(t, "user-1", "appA")
	otherUser := inst.dialSignedIn(t, "user-2", "appA")

	exhaustFrames(t, first, limits.PerUserClient-1)
	exhaustFrames(t, second, 1)
	send(t, second, frame{"type": "unsubscribe", "topic": "t"})

	expectError(t, second, "rate_limited")
	send(t, otherUser, frame{"type": "unsubscribe", "topic": "t"})
	if answered := receive(t, otherUser); answered["type"] != "unsubscribed" {
		t.Fatalf("another user was limited too: %v", answered)
	}
}

// exhaustFrames sends count frames and reads the answer to each.
func exhaustFrames(t *testing.T, socket *websocket.Conn, count int) {
	t.Helper()
	for sent := 0; sent < count; sent++ {
		send(t, socket, frame{"type": "unsubscribe", "topic": "t" + strconv.Itoa(sent%3)})
		if answered := receive(t, socket); answered["type"] != "unsubscribed" {
			t.Fatalf("frame %d answered with %v", sent, answered)
		}
	}
}

func TestOversizedMessagesAreRefusedAndTheConnectionStaysOpen(t *testing.T) {
	limits := relay.DefaultLimits
	limits.MaxDataBytes = 16
	inst := newInstance(t, miniredis.RunT(t).Addr(), limits)
	subscriber := inst.dialAnonymous(t, "appA")
	publisher := inst.dialAnonymous(t, "appA")
	subscribe(t, subscriber, "room-1")

	send(t, publisher, frame{"type": "publish", "topic": "room-1", "data": strings.Repeat("x", 17)})
	expectError(t, publisher, "message_too_large")
	send(t, publisher, frame{"type": "publish", "topic": "room-1", "data": strings.Repeat("x", 16)})

	expectMessage(t, subscriber, "room-1", strings.Repeat("x", 16))
}

func TestFramesBeyondTheReadLimitCloseTheConnection(t *testing.T) {
	limits := relay.DefaultLimits
	limits.MaxDataBytes = 16
	inst := newInstance(t, miniredis.RunT(t).Addr(), limits)
	socket := inst.dialAnonymous(t, "appA")

	send(t, socket, frame{"type": "publish", "topic": "room-1", "data": strings.Repeat("x", 5000)})

	_ = socket.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := socket.ReadMessage(); err == nil {
		t.Fatal("expected the connection to be closed")
	}
}

func TestSubscriptionsPerConnectionAreCapped(t *testing.T) {
	limits := relay.DefaultLimits
	limits.MaxSubscriptions = 2
	inst := newInstance(t, miniredis.RunT(t).Addr(), limits)
	socket := inst.dialAnonymous(t, "appA")
	subscribe(t, socket, "one")
	subscribe(t, socket, "two")
	subscribe(t, socket, "two")

	send(t, socket, frame{"type": "subscribe", "topic": "three"})

	expectError(t, socket, "subscription_limit")
}

func TestConnectionsPerIPAndPerUserAreCapped(t *testing.T) {
	limits := relay.DefaultLimits
	limits.MaxConnectionsPerIP = 1
	limits.MaxConnectionsPerUser = 2
	inst := newInstance(t, miniredis.RunT(t).Addr(), limits)
	inst.dialAnonymous(t, "appA")
	inst.dialSignedIn(t, "user-1", "appA")
	inst.dialSignedIn(t, "user-1", "appA")

	_, anonymousResponse, anonymousErr := websocket.DefaultDialer.Dial(inst.websocketURL("?client_id=appA"), nil)
	dialer := websocket.Dialer{Subprotocols: []string{relay.Subprotocol, "bearer.user-1@appA"}}
	_, signedInResponse, signedInErr := dialer.Dial(inst.websocketURL(""), nil)

	if anonymousErr == nil || anonymousResponse.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("anonymous connection over the cap: %v %v", anonymousResponse, anonymousErr)
	}
	if signedInErr == nil || signedInResponse.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("signed-in connection over the cap: %v %v", signedInResponse, signedInErr)
	}
}

func TestMalformedAndInvalidFramesGetErrors(t *testing.T) {
	inst := newInstance(t, miniredis.RunT(t).Addr(), relay.DefaultLimits)
	socket := inst.dialAnonymous(t, "appA")

	if err := socket.WriteMessage(websocket.TextMessage, []byte("not json")); err != nil {
		t.Fatal(err)
	}
	expectError(t, socket, "invalid_frame")
	send(t, socket, frame{"type": "dance"})
	expectError(t, socket, "invalid_frame")
	send(t, socket, frame{"type": "subscribe", "topic": ""})
	expectError(t, socket, "invalid_topic")
}

func dialStatus(dialer *websocket.Dialer, url string) int {
	socket, response, err := dialer.Dial(url, nil)
	if err == nil {
		_ = socket.Close()
		return http.StatusSwitchingProtocols
	}
	if response == nil {
		return 0
	}
	return response.StatusCode
}

func TestConnectionCapsHoldAcrossInstances(t *testing.T) {
	limits := relay.DefaultLimits
	limits.MaxConnectionsPerIP = 1
	redisServer := miniredis.RunT(t)
	firstInstance := newInstance(t, redisServer.Addr(), limits)
	secondInstance := newInstance(t, redisServer.Addr(), limits)
	firstInstance.dialAnonymous(t, "appA")

	status := dialStatus(websocket.DefaultDialer, secondInstance.websocketURL("?client_id=appA"))

	if status != http.StatusTooManyRequests {
		t.Fatalf("second connection on another instance answered %d", status)
	}
}

func TestClosingAConnectionFreesItsPlace(t *testing.T) {
	limits := relay.DefaultLimits
	limits.MaxConnectionsPerIP = 1
	inst := newInstance(t, miniredis.RunT(t).Addr(), limits)
	_ = inst.dialAnonymous(t, "appA").Close()

	deadline := time.Now().Add(2 * time.Second)
	for dialStatus(websocket.DefaultDialer, inst.websocketURL("?client_id=appA")) != http.StatusSwitchingProtocols {
		if time.Now().After(deadline) {
			t.Fatal("the place of a closed connection was never freed")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestExpiredLeasesOfACrashedInstanceDoNotCount(t *testing.T) {
	limits := relay.DefaultLimits
	limits.MaxConnectionsPerIP = 1
	redisServer := miniredis.RunT(t)
	inst := newInstance(t, redisServer.Addr(), limits)
	if _, err := redisServer.ZAdd("relay:connections:ip:127.0.0.1", 1, "crashed-instance"); err != nil {
		t.Fatalf("seed stale lease: %v", err)
	}

	inst.dialAnonymous(t, "appA")
}

func TestShutdownClosesConnectionsAsGoingAway(t *testing.T) {
	inst := newInstance(t, miniredis.RunT(t).Addr(), relay.DefaultLimits)
	socket := inst.dialAnonymous(t, "appA")

	inst.handler.Shutdown()

	_ = socket.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err := socket.ReadMessage()
	if !websocket.IsCloseError(err, websocket.CloseGoingAway) {
		t.Fatalf("expected a going away close, got %v", err)
	}
	status := dialStatus(websocket.DefaultDialer, inst.websocketURL("?client_id=appA"))
	if status == http.StatusSwitchingProtocols {
		t.Fatal("a connection was accepted after shutdown")
	}
}
