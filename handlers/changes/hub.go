package changes

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/storage/database"
)

var errShutDown = errors.New("change feed is shutting down")

// Limits are the caps and timings of the feed.
type Limits struct {
	// MaxStreamsPerUser caps the open streams of one account across every
	// instance sharing the Redis.
	MaxStreamsPerUser int
	// StreamBuffer is how many frames may wait for one slow client.
	StreamBuffer int
	// Heartbeat is how often an idle stream gets a comment, so proxies keep it.
	Heartbeat time.Duration
	// ReconnectDelay and MaxReconnectDelay bound the backoff before the hub
	// tries to restart a lost watch.
	ReconnectDelay    time.Duration
	MaxReconnectDelay time.Duration
	// RouteTimeout bounds the database lookups for one change.
	RouteTimeout time.Duration
}

var DefaultLimits = Limits{
	MaxStreamsPerUser: 10,
	StreamBuffer:      64,
	Heartbeat:         20 * time.Second,
	ReconnectDelay:    time.Second,
	MaxReconnectDelay: 30 * time.Second,
	RouteTimeout:      5 * time.Second,
}

// Hub watches the feed and hands each change to the streams it concerns.
type Hub struct {
	feed   Feed
	limits Limits
	cancel context.CancelFunc
	ctx    context.Context
	exited chan struct{}

	mutex    sync.Mutex
	started  bool
	watching bool
	shutDown bool
	streams  map[database.FeedRecipient]map[*stream]struct{}
}

func NewHub(feed Feed) *Hub {
	ctx, cancel := context.WithCancel(context.Background())
	return &Hub{
		feed: feed, limits: DefaultLimits, ctx: ctx, cancel: cancel, exited: make(chan struct{}),
		streams: map[database.FeedRecipient]map[*stream]struct{}{},
	}
}

func (hub *Hub) WithLimits(limits Limits) *Hub {
	hub.limits = limits
	return hub
}

// Start begins watching the database in the background.
func (hub *Hub) Start() {
	hub.mutex.Lock()
	hub.started = true
	hub.mutex.Unlock()
	go hub.run()
}

// Shutdown ends every open stream, refuses new ones and stops watching. It
// returns once the watch is closed. http.Server.Shutdown waits for open
// requests, so register it with RegisterOnShutdown.
func (hub *Hub) Shutdown() {
	hub.mutex.Lock()
	hub.shutDown = true
	for _, group := range hub.streams {
		for open := range group {
			open.close()
		}
	}
	started := hub.started
	hub.mutex.Unlock()
	hub.cancel()
	if started {
		<-hub.exited
	}
}

func (hub *Hub) run() {
	defer close(hub.exited)
	delay := hub.limits.ReconnectDelay
	for hub.ctx.Err() == nil {
		watch, err := hub.feed.WatchFeed(hub.ctx)
		if err != nil {
			slog.Warn("change feed watch", "error", err)
			delay = hub.waitBeforeRetry(delay)
			continue
		}
		delay = hub.limits.ReconnectDelay
		hub.setWatching(true)
		hub.broadcast(resyncMessage(reasonRestored))
		hub.dispatchUntilLost(watch)
		watch.Close()
		hub.setWatching(false)
		if hub.ctx.Err() == nil {
			hub.broadcast(resyncMessage(reasonLost))
		}
	}
}

func (hub *Hub) waitBeforeRetry(delay time.Duration) time.Duration {
	select {
	case <-hub.ctx.Done():
	case <-time.After(delay):
	}
	return min(delay*2, hub.limits.MaxReconnectDelay)
}

func (hub *Hub) setWatching(watching bool) {
	hub.mutex.Lock()
	defer hub.mutex.Unlock()
	hub.watching = watching
}

// Watching reports whether the live queries are running.
func (hub *Hub) Watching() bool {
	hub.mutex.Lock()
	defer hub.mutex.Unlock()
	return hub.watching
}

func (hub *Hub) dispatchUntilLost(watch Watch) {
	for {
		select {
		case <-hub.ctx.Done():
			return
		case <-watch.Lost():
			return
		case change := <-watch.Changes():
			hub.dispatch(change)
		}
	}
}

func (hub *Hub) dispatch(change database.FeedChange) {
	ctx, cancel := context.WithTimeout(hub.ctx, hub.limits.RouteTimeout)
	defer cancel()
	recipients, err := hub.feed.FeedRecipients(ctx, change)
	if err != nil {
		slog.Warn("change feed routing", "error", err, "seq", change.Seq)
		hub.broadcast(resyncMessage(reasonLost))
		return
	}
	msg := changeMessage(change.Collection, change.Seq)
	hub.mutex.Lock()
	defer hub.mutex.Unlock()
	for _, recipient := range recipients {
		hub.offerLocked(recipient, msg)
	}
}

// offerLocked sends the message to the recipient's streams whose token may read
// its collection.
func (hub *Hub) offerLocked(recipient database.FeedRecipient, msg message) {
	for open := range hub.streams[recipient] {
		if open.principal.CanRead(msg.collection) {
			open.send(msg)
		}
	}
}

func (hub *Hub) broadcast(msg message) {
	hub.mutex.Lock()
	defer hub.mutex.Unlock()
	for _, group := range hub.streams {
		for open := range group {
			open.send(msg)
		}
	}
}

// register adds the stream under its principal and returns the function that
// removes it. A stream opened while the watch is down is told to resync at once.
func (hub *Hub) register(open *stream) (func(), error) {
	hub.mutex.Lock()
	defer hub.mutex.Unlock()
	if hub.shutDown {
		return nil, errShutDown
	}
	key := principalKey(open.principal)
	if hub.streams[key] == nil {
		hub.streams[key] = map[*stream]struct{}{}
	}
	hub.streams[key][open] = struct{}{}
	if !hub.watching {
		open.send(resyncMessage(reasonLost))
	}
	return func() { hub.unregister(open) }, nil
}

func (hub *Hub) unregister(open *stream) {
	hub.mutex.Lock()
	defer hub.mutex.Unlock()
	key := principalKey(open.principal)
	delete(hub.streams[key], open)
	if len(hub.streams[key]) == 0 {
		delete(hub.streams, key)
	}
}

func principalKey(principal access.Principal) database.FeedRecipient {
	return database.FeedRecipient{Type: principal.Type(), ID: principal.ID()}
}
