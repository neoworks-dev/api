package changes_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/handlers/changes"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/database"
)

const (
	photos   = "@neoworks/photos"
	calendar = "@neoworks/calendar"
)

var fastLimits = changes.Limits{
	MaxStreamsPerUser: 3,
	StreamBuffer:      16,
	Heartbeat:         time.Minute,
	ReconnectDelay:    10 * time.Millisecond,
	MaxReconnectDelay: 20 * time.Millisecond,
	RouteTimeout:      time.Second,
}

type fakeWatch struct {
	changeChannel chan database.FeedChange
	lostChannel   chan struct{}
	closed        chan struct{}
}

func newFakeWatch() *fakeWatch {
	return &fakeWatch{changeChannel: make(chan database.FeedChange, 16), lostChannel: make(chan struct{}), closed: make(chan struct{})}
}

func (watch *fakeWatch) Changes() <-chan database.FeedChange { return watch.changeChannel }
func (watch *fakeWatch) Lost() <-chan struct{}               { return watch.lostChannel }
func (watch *fakeWatch) Close()                              { close(watch.closed) }

// fakeFeed hands out the watches a test queues and routes changes by a table of
// recipients.
type fakeFeed struct {
	mutex         sync.Mutex
	watches       chan *fakeWatch
	watchErrors   int
	recipients    map[string][]database.FeedRecipient
	head          int64
	headErr       error
	changed       bool
	changedErr    error
	changedCursor int64
	routeErr      error
}

func newFakeFeed() *fakeFeed {
	return &fakeFeed{watches: make(chan *fakeWatch, 8), recipients: map[string][]database.FeedRecipient{}}
}

func (feed *fakeFeed) WatchFeed(ctx context.Context) (changes.Watch, error) {
	feed.mutex.Lock()
	if feed.watchErrors > 0 {
		feed.watchErrors--
		feed.mutex.Unlock()
		return nil, errors.New("database unreachable")
	}
	feed.mutex.Unlock()
	select {
	case watch := <-feed.watches:
		return watch, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (feed *fakeFeed) FeedRecipients(_ context.Context, change database.FeedChange) ([]database.FeedRecipient, error) {
	feed.mutex.Lock()
	defer feed.mutex.Unlock()
	return feed.recipients[change.NodeID], feed.routeErr
}

func (feed *fakeFeed) FeedHead(context.Context) (int64, error) {
	feed.mutex.Lock()
	defer feed.mutex.Unlock()
	return feed.head, feed.headErr
}

func (feed *fakeFeed) HasChangesSince(_ context.Context, _ access.Principal, cursor int64) (bool, error) {
	feed.mutex.Lock()
	defer feed.mutex.Unlock()
	feed.changedCursor = cursor
	return feed.changed, feed.changedErr
}

func (feed *fakeFeed) routeTo(nodeID string, recipients ...database.FeedRecipient) {
	feed.mutex.Lock()
	defer feed.mutex.Unlock()
	feed.recipients[nodeID] = recipients
}

func (feed *fakeFeed) failRouting(err error) {
	feed.mutex.Lock()
	defer feed.mutex.Unlock()
	feed.routeErr = err
}

func user(userID string) database.FeedRecipient {
	return database.FeedRecipient{Type: access.PrincipalTypeUser, ID: userID}
}

// signIn reads the principal from headers, standing in for token verification.
// X-Expires-In, in milliseconds, gives the token an expiry.
func signIn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scopes := strings.Split(r.Header.Get("X-Scopes"), ",")
		principal := access.Principal{
			UserID: r.Header.Get("X-User"), InstallID: r.Header.Get("X-Install"), ClientID: "app", Scopes: scopes,
		}
		ctx := middleware.ContextWithPrincipal(r.Context(), principal)
		if expiresIn := r.Header.Get("X-Expires-In"); expiresIn != "" {
			milliseconds, _ := strconv.Atoi(expiresIn)
			claims := &oauth.Claims{RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(milliseconds) * time.Millisecond)),
			}}
			ctx = middleware.NewContextWithClaim(ctx, claims)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type feedServer struct {
	server *httptest.Server
	hub    *changes.Hub
	feed   *fakeFeed
}

func newFeedServer(t *testing.T, limits changes.Limits) *feedServer {
	t.Helper()
	feed := newFakeFeed()
	hub := changes.NewHub(feed).WithLimits(limits)
	router := chi.NewRouter()
	router.Group(func(authenticated chi.Router) {
		authenticated.Use(signIn)
		changes.NewHandler(hub, feed).RegisterAuthenticated(authenticated)
	})
	server := httptest.NewUnstartedServer(router)
	server.Config.RegisterOnShutdown(hub.Shutdown)
	server.Start()
	t.Cleanup(func() {
		hub.Shutdown()
		server.Close()
	})
	return &feedServer{server: server, hub: hub, feed: feed}
}

// startWatching queues a watch, starts the hub and waits until it uses it.
func (fixture *feedServer) startWatching(t *testing.T) *fakeWatch {
	t.Helper()
	watch := newFakeWatch()
	fixture.feed.watches <- watch
	fixture.hub.Start()
	return watch
}

type event struct {
	id   string
	name string
	data string
}

// sseStream reads events and comments off an open response.
type sseStream struct {
	response *http.Response
	events   chan event
	comments chan string
	cancel   context.CancelFunc
}

type clientOptions struct {
	userID      string
	installID   string
	scopes      string
	lastEventID string
	expiresInMs string
}

func (fixture *feedServer) open(t *testing.T, options clientOptions) *sseStream {
	t.Helper()
	stream, status := fixture.tryOpen(t, options)
	if status != http.StatusOK {
		t.Fatalf("open stream: status %d", status)
	}
	return stream
}

func (fixture *feedServer) tryOpen(t *testing.T, options clientOptions) (*sseStream, int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, fixture.server.URL+"/api/v1/changes", nil)
	request.Header.Set("X-User", options.userID)
	request.Header.Set("X-Install", options.installID)
	request.Header.Set("X-Scopes", options.scopes)
	request.Header.Set("X-Expires-In", options.expiresInMs)
	request.Header.Set("Last-Event-ID", options.lastEventID)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		cancel()
		t.Fatalf("open stream: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		cancel()
		response.Body.Close()
		return nil, response.StatusCode
	}
	stream := &sseStream{response: response, events: make(chan event, 64), comments: make(chan string, 64), cancel: cancel}
	t.Cleanup(stream.close)
	go stream.read()
	return stream, response.StatusCode
}

func (stream *sseStream) close() {
	stream.cancel()
	stream.response.Body.Close()
}

func (stream *sseStream) read() {
	defer close(stream.events)
	scanner := bufio.NewScanner(stream.response.Body)
	var pending event
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			if pending.name != "" {
				stream.events <- pending
			}
			pending = event{}
		case strings.HasPrefix(line, ": "):
			stream.comments <- strings.TrimPrefix(line, ": ")
		case strings.HasPrefix(line, "id: "):
			pending.id = strings.TrimPrefix(line, "id: ")
		case strings.HasPrefix(line, "event: "):
			pending.name = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			pending.data = strings.TrimPrefix(line, "data: ")
		}
	}
}

func (stream *sseStream) next(t *testing.T) event {
	t.Helper()
	select {
	case received, open := <-stream.events:
		if !open {
			t.Fatal("stream ended while waiting for an event")
		}
		return received
	case <-time.After(3 * time.Second):
		t.Fatal("no event arrived")
		return event{}
	}
}

func (stream *sseStream) expectSilence(t *testing.T) {
	t.Helper()
	select {
	case received, open := <-stream.events:
		if open {
			t.Fatalf("unexpected event %+v", received)
		}
		t.Fatal("stream ended unexpectedly")
	case <-time.After(150 * time.Millisecond):
	}
}

// expectEnd waits for the server to end the stream, ignoring events that were
// queued before it did.
func (stream *sseStream) expectEnd(t *testing.T) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case _, open := <-stream.events:
			if !open {
				return
			}
		case <-deadline:
			t.Fatal("stream did not end")
		}
	}
}

func (stream *sseStream) expectComment(t *testing.T, wanted string) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case comment := <-stream.comments:
			if comment == wanted {
				return
			}
		case <-deadline:
			t.Fatalf("no %q comment arrived", wanted)
		}
	}
}

func (received event) decode(t *testing.T) map[string]any {
	t.Helper()
	var data map[string]any
	if err := json.Unmarshal([]byte(received.data), &data); err != nil {
		t.Fatalf("decode %q: %v", received.data, err)
	}
	return data
}

func (received event) expectChange(t *testing.T, collection string, seq int64) {
	t.Helper()
	data := received.decode(t)
	if received.name != "change" || received.id != strconv.FormatInt(seq, 10) || data["collection"] != collection || data["seq"] != float64(seq) {
		t.Fatalf("expected change %s at %d, got %+v", collection, seq, received)
	}
}

func (received event) expectResync(t *testing.T, reason string) map[string]any {
	t.Helper()
	data := received.decode(t)
	if received.name != "resync" || data["reason"] != reason {
		t.Fatalf("expected resync %q, got %+v", reason, received)
	}
	return data
}

func (watch *fakeWatch) push(nodeID string, collection string, seq int64) {
	watch.changeChannel <- database.FeedChange{Table: "node", NodeID: nodeID, Collection: collection, Seq: seq}
}

// awaitRestored reads the resync the hub broadcasts when its watch starts, which
// streams opened before it receive.
func awaitRestored(t *testing.T, streams ...*sseStream) {
	t.Helper()
	for _, stream := range streams {
		stream.next(t).expectResync(t, "restored")
	}
}

func TestChangeGoesOnlyToItsRecipientsWithItsSequenceAsEventID(t *testing.T) {
	fixture := newFeedServer(t, fastLimits)
	owner := fixture.open(t, clientOptions{userID: "owner", scopes: photos + ":read"})
	viewer := fixture.open(t, clientOptions{userID: "viewer", scopes: photos + ":read"})
	stranger := fixture.open(t, clientOptions{userID: "stranger", scopes: photos + ":read"})
	owner.next(t).expectResync(t, "lost")
	viewer.next(t).expectResync(t, "lost")
	stranger.next(t).expectResync(t, "lost")
	watch := fixture.startWatching(t)
	awaitRestored(t, owner, viewer, stranger)

	fixture.feed.routeTo("node-1", user("owner"), user("viewer"))
	watch.push("node-1", photos, 42)

	owner.next(t).expectChange(t, photos, 42)
	viewer.next(t).expectChange(t, photos, 42)
	stranger.expectSilence(t)
}

func TestConnectionOnlyReceivesCollectionsItsScopesMayRead(t *testing.T) {
	fixture := newFeedServer(t, fastLimits)
	photosOnly := fixture.open(t, clientOptions{userID: "owner", scopes: photos + ":read"})
	writeScope := fixture.open(t, clientOptions{userID: "owner", scopes: calendar + ":write"})
	shareOnly := fixture.open(t, clientOptions{userID: "owner", scopes: calendar + ":share"})
	for _, stream := range []*sseStream{photosOnly, writeScope, shareOnly} {
		stream.next(t).expectResync(t, "lost")
	}
	watch := fixture.startWatching(t)
	awaitRestored(t, photosOnly, writeScope, shareOnly)

	fixture.feed.routeTo("event", user("owner"))
	watch.push("event", calendar, 7)

	writeScope.next(t).expectChange(t, calendar, 7)
	photosOnly.expectSilence(t)
	shareOnly.expectSilence(t)
}

func TestInstallConnectionIsAddressedAsItsInstallNotItsUser(t *testing.T) {
	fixture := newFeedServer(t, fastLimits)
	asInstall := fixture.open(t, clientOptions{userID: "owner", installID: "phone", scopes: photos + ":read"})
	asUser := fixture.open(t, clientOptions{userID: "owner", scopes: photos + ":read"})
	asInstall.next(t).expectResync(t, "lost")
	asUser.next(t).expectResync(t, "lost")
	watch := fixture.startWatching(t)
	awaitRestored(t, asInstall, asUser)

	fixture.feed.routeTo("shared", database.FeedRecipient{Type: access.PrincipalTypeInstall, ID: "phone"})
	watch.push("shared", photos, 3)

	asInstall.next(t).expectChange(t, photos, 3)
	asUser.expectSilence(t)
}

func TestEventIDsNeverGoBackwardsWhenAChangeArrivesLate(t *testing.T) {
	fixture := newFeedServer(t, fastLimits)
	owner := fixture.open(t, clientOptions{userID: "owner", scopes: photos + ":read"})
	owner.next(t).expectResync(t, "lost")
	watch := fixture.startWatching(t)
	awaitRestored(t, owner)

	fixture.feed.routeTo("node", user("owner"))
	watch.push("node", photos, 9)
	watch.push("node", photos, 4)

	owner.next(t).expectChange(t, photos, 9)
	owner.next(t).expectChange(t, photos, 9)
}

func TestStreamAnnouncesItselfAndKeepsAliveWithHeartbeats(t *testing.T) {
	limits := fastLimits
	limits.Heartbeat = 20 * time.Millisecond
	fixture := newFeedServer(t, limits)
	owner := fixture.open(t, clientOptions{userID: "owner", scopes: photos + ":read"})

	if contentType := owner.response.Header.Get("Content-Type"); contentType != "text/event-stream" {
		t.Fatalf("content type %q", contentType)
	}
	owner.expectComment(t, "connected")
	owner.expectComment(t, "heartbeat")
	owner.expectComment(t, "heartbeat")
}

func TestResumeTellsAClientThatMissedChangesToResync(t *testing.T) {
	fixture := newFeedServer(t, fastLimits)
	fixture.feed.head = 50
	fixture.feed.changed = true
	fixture.startWatching(t)

	owner := fixture.open(t, clientOptions{userID: "owner", scopes: photos + ":read", lastEventID: "40"})

	data := owner.next(t).expectResync(t, "missed")
	if data["seq"] != float64(50) {
		t.Fatalf("resync should name the feed head: %v", data)
	}
	if fixture.feed.changedCursor != 40 {
		t.Fatalf("catch-up should check from Last-Event-ID, checked from %d", fixture.feed.changedCursor)
	}
}

func TestResyncEventCarriesTheHeadAsItsID(t *testing.T) {
	fixture := newFeedServer(t, fastLimits)
	fixture.feed.head = 50
	fixture.feed.changed = true
	fixture.startWatching(t)

	owner := fixture.open(t, clientOptions{userID: "owner", scopes: photos + ":read", lastEventID: "40"})

	if received := owner.next(t); received.id != "50" {
		t.Fatalf("a resync that knows the head carries it as its id: %+v", received)
	}
}

func TestResumeStaysQuietWhenNothingWasMissed(t *testing.T) {
	fixture := newFeedServer(t, fastLimits)
	fixture.feed.head = 50
	fixture.feed.changed = false
	fixture.startWatching(t)

	atHead := fixture.open(t, clientOptions{userID: "owner", scopes: photos + ":read", lastEventID: "50"})
	otherPeoplesChanges := fixture.open(t, clientOptions{userID: "owner", scopes: photos + ":read", lastEventID: "40"})

	awaitRestoredIfAny(t, atHead)
	awaitRestoredIfAny(t, otherPeoplesChanges)
	atHead.expectSilence(t)
	otherPeoplesChanges.expectSilence(t)
}

// awaitRestoredIfAny drops the restored resync a stream that opened before the
// watch started may have received.
func awaitRestoredIfAny(t *testing.T, stream *sseStream) {
	t.Helper()
	select {
	case received := <-stream.events:
		received.expectResync(t, "restored")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestResumeFromAFutureSequenceResyncs(t *testing.T) {
	fixture := newFeedServer(t, fastLimits)
	fixture.feed.head = 10
	fixture.startWatching(t)

	owner := fixture.open(t, clientOptions{userID: "owner", scopes: photos + ":read", lastEventID: "99"})

	data := owner.next(t).expectResync(t, "missed")
	if data["seq"] != float64(10) {
		t.Fatalf("a client ahead of the feed starts over from the head: %v", data)
	}
}

func TestResumeFailsSafeWhenTheDatabaseCannotAnswer(t *testing.T) {
	fixture := newFeedServer(t, fastLimits)
	fixture.feed.head = 50
	fixture.feed.changedErr = errors.New("database unreachable")
	fixture.startWatching(t)

	owner := fixture.open(t, clientOptions{userID: "owner", scopes: photos + ":read", lastEventID: "40"})

	owner.next(t).expectResync(t, "lost")
}

func TestMalformedLastEventIDIsRefused(t *testing.T) {
	fixture := newFeedServer(t, fastLimits)
	for _, lastEventID := range []string{"abc", "-3", "1.5"} {
		_, status := fixture.tryOpen(t, clientOptions{userID: "owner", scopes: photos + ":read", lastEventID: lastEventID})
		if status != http.StatusBadRequest {
			t.Fatalf("Last-Event-ID %q: status %d", lastEventID, status)
		}
	}
}

func TestLosingTheWatchTellsClientsToResyncAndRecoveryDoesAgain(t *testing.T) {
	fixture := newFeedServer(t, fastLimits)
	owner := fixture.open(t, clientOptions{userID: "owner", scopes: photos + ":read"})
	owner.next(t).expectResync(t, "lost")
	first := fixture.startWatching(t)
	awaitRestored(t, owner)

	second := newFakeWatch()
	fixture.feed.watches <- second
	close(first.lostChannel)

	owner.next(t).expectResync(t, "lost")
	owner.next(t).expectResync(t, "restored")
	select {
	case <-first.closed:
	case <-time.After(time.Second):
		t.Fatal("the lost watch should be closed")
	}
	fixture.feed.routeTo("node", user("owner"))
	second.push("node", photos, 11)
	owner.next(t).expectChange(t, photos, 11)
}

func TestHubKeepsRetryingWhileTheDatabaseIsDown(t *testing.T) {
	fixture := newFeedServer(t, fastLimits)
	fixture.feed.watchErrors = 3
	owner := fixture.open(t, clientOptions{userID: "owner", scopes: photos + ":read"})
	owner.next(t).expectResync(t, "lost")
	watch := fixture.startWatching(t)

	owner.next(t).expectResync(t, "restored")
	fixture.feed.routeTo("node", user("owner"))
	watch.push("node", photos, 5)
	owner.next(t).expectChange(t, photos, 5)
}

func TestRoutingFailureTellsEveryoneToResync(t *testing.T) {
	fixture := newFeedServer(t, fastLimits)
	owner := fixture.open(t, clientOptions{userID: "owner", scopes: photos + ":read"})
	owner.next(t).expectResync(t, "lost")
	watch := fixture.startWatching(t)
	awaitRestored(t, owner)

	fixture.feed.failRouting(errors.New("database unreachable"))
	watch.push("node", photos, 5)

	owner.next(t).expectResync(t, "lost")
}

func TestStreamsPerUserAreCapped(t *testing.T) {
	fixture := newFeedServer(t, fastLimits)
	options := clientOptions{userID: "owner", scopes: photos + ":read"}
	var opened []*sseStream
	for range fastLimits.MaxStreamsPerUser {
		opened = append(opened, fixture.open(t, options))
	}

	if _, status := fixture.tryOpen(t, options); status != http.StatusTooManyRequests {
		t.Fatalf("one stream too many: status %d", status)
	}
	if _, status := fixture.tryOpen(t, clientOptions{userID: "someone-else", scopes: photos + ":read"}); status != http.StatusOK {
		t.Fatalf("another user is not affected: status %d", status)
	}
	opened[0].close()
	waitUntilAdmitted(t, fixture, options)
}

func waitUntilAdmitted(t *testing.T, fixture *feedServer, options clientOptions) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		stream, status := fixture.tryOpen(t, options)
		if status == http.StatusOK {
			stream.close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("closing a stream did not free its place")
}

func TestStreamEndsWhenItsTokenExpires(t *testing.T) {
	fixture := newFeedServer(t, fastLimits)
	owner := fixture.open(t, clientOptions{userID: "owner", scopes: photos + ":read", expiresInMs: "100"})

	owner.expectEnd(t)
}

func TestShutdownEndsOpenStreamsAndRefusesNewOnes(t *testing.T) {
	fixture := newFeedServer(t, fastLimits)
	fixture.startWatching(t)
	owner := fixture.open(t, clientOptions{userID: "owner", scopes: photos + ":read"})
	awaitRestoredIfAny(t, owner)

	shutdownContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := fixture.server.Config.Shutdown(shutdownContext); err != nil {
		t.Fatalf("http shutdown should finish once the streams end: %v", err)
	}

	owner.expectEnd(t)
}

func TestHubRefusesStreamsAfterShutdown(t *testing.T) {
	fixture := newFeedServer(t, fastLimits)
	fixture.startWatching(t)
	fixture.hub.Shutdown()

	if _, status := fixture.tryOpen(t, clientOptions{userID: "owner", scopes: photos + ":read"}); status != http.StatusServiceUnavailable {
		t.Fatalf("status %d", status)
	}
}

func TestShutdownClosesTheWatch(t *testing.T) {
	fixture := newFeedServer(t, fastLimits)
	watch := fixture.startWatching(t)
	fixture.open(t, clientOptions{userID: "owner", scopes: photos + ":read"})

	fixture.hub.Shutdown()

	select {
	case <-watch.closed:
	case <-time.After(time.Second):
		t.Fatal("the watch should be closed")
	}
}

func TestShutdownWithoutStartReturns(t *testing.T) {
	hub := changes.NewHub(newFakeFeed())
	done := make(chan struct{})
	go func() {
		hub.Shutdown()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Shutdown blocked on a hub that never started")
	}
}

func itoa(value int64) string {
	return strconv.FormatInt(value, 10)
}

func timeAfterQuiet() <-chan time.Time {
	return time.After(300 * time.Millisecond)
}

// nextResync reads events until a resync with the reason arrives.
func (stream *sseStream) nextResync(t *testing.T, reason string) event {
	t.Helper()
	for {
		received := stream.next(t)
		if received.name == "resync" && received.decode(t)["reason"] == reason {
			return received
		}
	}
}

func (stream *sseStream) expectNoResync(t *testing.T, reason string) {
	t.Helper()
	for {
		select {
		case received, open := <-stream.events:
			if open && received.name == "resync" && received.decode(t)["reason"] == reason {
				t.Fatalf("unexpected resync %+v", received)
			}
			if !open {
				return
			}
		case <-timeAfterQuiet():
			return
		}
	}
}
