package changes

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/connectionlease"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/middleware"
)

type Handler struct {
	hub    *Hub
	feed   Feed
	leases connectionlease.Leases
}

func NewHandler(hub *Hub, feed Feed, leases connectionlease.Leases) *Handler {
	return &Handler{hub: hub, feed: feed, leases: leases}
}

// RegisterAuthenticated mounts the stream behind the principal middleware.
func (handler *Handler) RegisterAuthenticated(router chi.Router) {
	router.Get("/api/v1/changes", handler.stream)
}

func (handler *Handler) stream(w http.ResponseWriter, r *http.Request) {
	principal, found := middleware.PrincipalFromContext(r.Context())
	if !found {
		respond.Error(w, http.StatusUnauthorized, "invalid_token", "no principal")
		return
	}
	lastEventID, hasLastEventID, valid := parseLastEventID(r)
	if !valid {
		respond.Error(w, http.StatusBadRequest, "invalid_last_event_id", "Last-Event-ID must be a sequence number")
		return
	}
	releaseLease, admitted := handler.admit(w, r, principal.UserID)
	if !admitted {
		return
	}
	defer releaseLease()
	open := newStream(principal, handler.hub.limits.StreamBuffer)
	release, err := handler.hub.register(open)
	if err != nil {
		respond.Error(w, http.StatusServiceUnavailable, "unavailable", "change feed is shutting down")
		return
	}
	defer release()

	flusher := http.NewResponseController(w)
	writeStreamHeaders(w)
	if !writeFrame(w, flusher, openingFrame) {
		return
	}
	if hasLastEventID {
		handler.announceMissed(r.Context(), open, lastEventID)
	}
	handler.pump(r.Context(), open, w, flusher)
}

// admit takes one of the user's stream places in Redis and keeps it renewed
// until the returned function releases it. It answers the request itself when
// the user is at the cap or Redis is unreachable.
func (handler *Handler) admit(w http.ResponseWriter, r *http.Request, userID string) (func(), bool) {
	lease, admitted, err := handler.leases.Acquire(r.Context(), "changes:streams:user:"+userID, handler.hub.limits.MaxStreamsPerUser)
	if err != nil {
		slog.Warn("change stream lease", "error", err)
		respond.Error(w, http.StatusServiceUnavailable, "unavailable", "change feed is unavailable")
		return nil, false
	}
	if !admitted {
		respond.Error(w, http.StatusTooManyRequests, "too_many_streams", "too many open change streams")
		return nil, false
	}
	held := make(chan struct{})
	go handler.leases.Hold(lease, held)
	return func() {
		close(held)
		handler.leases.Release(lease)
	}, true
}

func writeStreamHeaders(w http.ResponseWriter) {
	header := w.Header()
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-cache, no-transform")
	header.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
}

func writeFrame(w http.ResponseWriter, flusher *http.ResponseController, frame []byte) bool {
	if _, err := w.Write(frame); err != nil {
		return false
	}
	return flusher.Flush() == nil
}

// pump writes queued frames and heartbeats until the client leaves, the stream
// is closed, the hub shuts down or the token expires.
func (handler *Handler) pump(ctx context.Context, open *stream, w http.ResponseWriter, flusher *http.ResponseController) {
	heartbeat := time.NewTicker(handler.hub.limits.Heartbeat)
	defer heartbeat.Stop()
	expired, stopExpiry := tokenExpiry(ctx)
	defer stopExpiry()
	var highest int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-open.done:
			return
		case <-expired:
			return
		case <-heartbeat.C:
			if !writeFrame(w, flusher, heartbeatFrame) {
				return
			}
		case msg := <-open.messages:
			var frame []byte
			frame, highest = encodeFrame(msg, highest)
			if !writeFrame(w, flusher, frame) {
				return
			}
		}
	}
}

// tokenExpiry fires when the access token the stream was opened with expires,
// so the client reconnects with a fresh one instead of streaming on a dead token.
func tokenExpiry(ctx context.Context) (<-chan time.Time, func()) {
	claims := middleware.ClaimFromContext(ctx)
	if claims == nil || claims.ExpiresAt == nil {
		return nil, func() {}
	}
	timer := time.NewTimer(time.Until(claims.ExpiresAt.Time))
	return timer.C, func() { timer.Stop() }
}

// announceMissed queues a resync when the principal has changes after the
// sequence the client last saw. The stream is registered before this runs, so
// a change that lands meanwhile is delivered as an event instead of lost.
func (handler *Handler) announceMissed(ctx context.Context, open *stream, lastEventID int64) {
	head, err := handler.feed.FeedHead(ctx)
	if err != nil {
		slog.Warn("change feed head", "error", err)
		open.send(resyncMessage(reasonLost))
		return
	}
	if head == lastEventID {
		return
	}
	missed, err := handler.feed.HasChangesSince(ctx, open.principal, lastEventID)
	if err != nil {
		slog.Warn("change feed catch-up", "error", err)
		open.send(resyncMessage(reasonLost))
		return
	}
	if missed || head < lastEventID {
		open.send(resyncMessageAt(reasonMissed, head))
	}
}

func parseLastEventID(r *http.Request) (value int64, present bool, valid bool) {
	header := r.Header.Get("Last-Event-ID")
	if header == "" {
		return 0, false, true
	}
	value, err := strconv.ParseInt(header, 10, 64)
	if err != nil || value < 0 {
		return 0, true, false
	}
	return value, true, true
}
