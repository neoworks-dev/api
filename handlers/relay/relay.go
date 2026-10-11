// Package relay is a realtime publish and subscribe service over one WebSocket
// endpoint. Topics are opaque strings chosen by apps and namespaced by the OAuth
// client of the connection; message data is opaque to the server and nothing is
// stored. The wire protocol is documented in neoworks.dev#44.
package relay

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/neoworks/auth/connectionlease"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/ratelimit"
	"github.com/neoworks/auth/storage/database"
)

// Subprotocol is offered by clients so a browser, which cannot set headers on a
// WebSocket, can pass its access token as a second protocol "bearer.<token>".
const (
	Subprotocol       = "neoworks.relay.v1"
	bearerSubprotocol = "bearer."
)

// Limits are the caps on one connection and on the connections of one caller.
type Limits struct {
	MaxDataBytes          int
	MaxTopicBytes         int
	MaxSubscriptions      int
	MaxConnectionsPerUser int
	MaxConnectionsPerIP   int
}

var DefaultLimits = Limits{
	MaxDataBytes:          64 * 1024,
	MaxTopicBytes:         256,
	MaxSubscriptions:      32,
	MaxConnectionsPerUser: 10,
	MaxConnectionsPerIP:   5,
}

// ClientLookup finds registered OAuth clients.
type ClientLookup interface {
	GetClient(ctx context.Context, clientID string) (*oauth.Client, error)
}

// FrameLimiter limits the frames a connection sends.
type FrameLimiter interface {
	TakeUser(ctx context.Context, bucket ratelimit.Bucket, clientID string, userID string) time.Duration
	TakeIP(ctx context.Context, bucket ratelimit.Bucket, ip string) time.Duration
}

type Handler struct {
	hub     *Hub
	clients ClientLookup
	limiter FrameLimiter
	limits  Limits
	upgrade websocket.Upgrader

	leases connectionlease.Leases

	mutex       sync.Mutex
	shutDown    bool
	connections map[*connection]struct{}
}

func NewHandler(hub *Hub, clients ClientLookup, limiter FrameLimiter) *Handler {
	return &Handler{
		hub: hub, clients: clients, limiter: limiter, limits: DefaultLimits,
		leases: connectionlease.New(hub.client), connections: map[*connection]struct{}{},
		// Tokens travel in a header or subprotocol, never a cookie, so the
		// origin of the page gives an attacker nothing to ride on.
		upgrade: websocket.Upgrader{
			Subprotocols: []string{Subprotocol},
			CheckOrigin:  func(*http.Request) bool { return true },
		},
	}
}

func (handler *Handler) WithLimits(limits Limits) *Handler {
	handler.limits = limits
	return handler
}

// SignedIn serves connections whose principal the middleware in front of it
// resolved; they belong to the client the token was issued to.
func (handler *Handler) SignedIn() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, found := middleware.PrincipalFromContext(r.Context())
		if !found {
			respond.Error(w, http.StatusUnauthorized, "invalid_token", "no principal")
			return
		}
		handler.serve(w, r, identity{clientID: principal.ClientID, userID: principal.UserID, ip: ratelimit.ClientIP(r)})
	})
}

// Anonymous serves connections identified only by the registered client in the
// client_id query parameter.
func (handler *Handler) Anonymous() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID := r.URL.Query().Get("client_id")
		if clientID == "" {
			respond.Error(w, http.StatusBadRequest, "client_id_required", "an anonymous connection needs a client_id")
			return
		}
		_, err := handler.clients.GetClient(r.Context(), clientID)
		if errors.Is(err, database.ErrNotFound) {
			respond.Error(w, http.StatusForbidden, "unknown_client", "client_id is not a registered client")
			return
		}
		if err != nil {
			slog.Warn("relay client lookup", "error", err)
			respond.Error(w, http.StatusServiceUnavailable, "unavailable", "relay is unavailable")
			return
		}
		handler.serve(w, r, identity{clientID: clientID, ip: ratelimit.ClientIP(r)})
	})
}

func (handler *Handler) serve(w http.ResponseWriter, r *http.Request, who identity) {
	if handler.isShutDown() {
		respond.Error(w, http.StatusServiceUnavailable, "unavailable", "relay is shutting down")
		return
	}
	held, admitted, err := handler.leases.Acquire(r.Context(), leaseKey(who), handler.connectionLimit(who))
	if err != nil {
		slog.Warn("relay connection lease", "error", err)
		respond.Error(w, http.StatusServiceUnavailable, "unavailable", "relay is unavailable")
		return
	}
	if !admitted {
		respond.Error(w, http.StatusTooManyRequests, "too_many_connections", "too many open relay connections")
		return
	}
	defer handler.leases.Release(held)
	socket, err := handler.upgrade.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	conn := newConnection(handler, socket, who)
	if !handler.track(conn) {
		conn.goAway()
		return
	}
	defer handler.untrack(conn)
	go handler.leases.Hold(held, conn.done)
	conn.run(r.Context())
}

func (handler *Handler) connectionLimit(who identity) int {
	if who.signedIn() {
		return handler.limits.MaxConnectionsPerUser
	}
	return handler.limits.MaxConnectionsPerIP
}

func (handler *Handler) isShutDown() bool {
	handler.mutex.Lock()
	defer handler.mutex.Unlock()
	return handler.shutDown
}

func (handler *Handler) track(conn *connection) bool {
	handler.mutex.Lock()
	defer handler.mutex.Unlock()
	if handler.shutDown {
		return false
	}
	handler.connections[conn] = struct{}{}
	return true
}

func (handler *Handler) untrack(conn *connection) {
	handler.mutex.Lock()
	defer handler.mutex.Unlock()
	delete(handler.connections, conn)
}

// Shutdown tells every open connection the server is going away and refuses
// new ones. http.Server.Shutdown does not see hijacked connections, so register
// it with RegisterOnShutdown.
func (handler *Handler) Shutdown() {
	handler.mutex.Lock()
	defer handler.mutex.Unlock()
	handler.shutDown = true
	for conn := range handler.connections {
		conn.goAway()
	}
}

// ChooseByToken sends a request that carries an access token to signedIn and
// every other request to anonymous. A token that fails verification is refused
// by signedIn; it never falls back to anonymous.
func ChooseByToken(signedIn http.Handler, anonymous http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := accessToken(r)
		if token == "" {
			anonymous.ServeHTTP(w, r)
			return
		}
		r.Header.Set("Authorization", "Bearer "+token)
		signedIn.ServeHTTP(w, r)
	})
}

func accessToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		return header[len("Bearer "):]
	}
	for _, line := range r.Header.Values("Sec-WebSocket-Protocol") {
		token := bearerFromProtocols(line)
		if token != "" {
			return token
		}
	}
	return ""
}

func bearerFromProtocols(line string) string {
	for _, protocol := range strings.Split(line, ",") {
		protocol = strings.TrimSpace(protocol)
		if strings.HasPrefix(protocol, bearerSubprotocol) {
			return protocol[len(bearerSubprotocol):]
		}
	}
	return ""
}
