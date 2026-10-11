package relay

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/neoworks/auth/ratelimit"
)

const (
	outgoingBuffer = 64
	writeTimeout   = 10 * time.Second
	pingInterval   = 30 * time.Second
	pongTimeout    = 70 * time.Second
	// readLimitOverhead is room for the JSON around the topic and data of a frame.
	readLimitOverhead = 1024
)

// identity is who a connection is: its OAuth client always, its user when it is
// signed in, and the IP it came from.
type identity struct {
	clientID string
	userID   string
	ip       string
}

func (who identity) signedIn() bool {
	return who.userID != ""
}

type connection struct {
	handler  *Handler
	socket   *websocket.Conn
	who      identity
	outgoing chan []byte
	done     chan struct{}
	closing  sync.Once
	// topics maps each subscribed topic to its Redis channel; only the read
	// loop touches it.
	topics map[string]string
}

func newConnection(handler *Handler, socket *websocket.Conn, who identity) *connection {
	return &connection{
		handler: handler, socket: socket, who: who,
		outgoing: make(chan []byte, outgoingBuffer), done: make(chan struct{}), topics: map[string]string{},
	}
}

// send queues a frame without blocking. A connection that cannot keep up is
// closed rather than slowing down everyone who publishes to its topics.
func (conn *connection) send(frame []byte) {
	select {
	case conn.outgoing <- frame:
	default:
		conn.close()
	}
}

func (conn *connection) close() {
	conn.closing.Do(func() {
		close(conn.done)
		_ = conn.socket.Close()
	})
}

// run serves the connection until the client leaves or it is closed.
func (conn *connection) run(ctx context.Context) {
	go conn.writeLoop()
	defer conn.leave()
	conn.socket.SetReadLimit(int64(conn.handler.limits.MaxDataBytes + conn.handler.limits.MaxTopicBytes + readLimitOverhead))
	_ = conn.socket.SetReadDeadline(time.Now().Add(pongTimeout))
	conn.socket.SetPongHandler(func(string) error {
		return conn.socket.SetReadDeadline(time.Now().Add(pongTimeout))
	})
	for {
		_, raw, err := conn.socket.ReadMessage()
		if err != nil {
			return
		}
		conn.handleFrame(ctx, raw)
	}
}

func (conn *connection) leave() {
	conn.close()
	for _, channel := range conn.topics {
		conn.handler.hub.Unsubscribe(conn, channel)
	}
}

func (conn *connection) writeLoop() {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()
	for {
		select {
		case frame := <-conn.outgoing:
			if !conn.write(websocket.TextMessage, frame) {
				return
			}
		case <-ticker.C:
			if !conn.write(websocket.PingMessage, nil) {
				return
			}
		case <-conn.done:
			return
		}
	}
}

func (conn *connection) write(messageType int, payload []byte) bool {
	_ = conn.socket.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := conn.socket.WriteMessage(messageType, payload); err != nil {
		conn.close()
		return false
	}
	return true
}

func (conn *connection) handleFrame(ctx context.Context, raw []byte) {
	var frame clientFrame
	if err := json.Unmarshal(raw, &frame); err != nil {
		conn.send(encodeError(codeInvalidFrame, "frame is not valid JSON of the expected shape", "", 0))
		return
	}
	if wait := conn.takeFrame(ctx); wait > 0 {
		seconds := int(math.Ceil(wait.Seconds()))
		conn.send(encodeError(codeRateLimited, "too many frames; retry after the delay", frame.Topic, seconds))
		return
	}
	switch frame.Type {
	case frameSubscribe:
		conn.subscribe(ctx, frame.Topic)
	case frameUnsubscribe:
		conn.unsubscribe(frame.Topic)
	case framePublish:
		conn.publish(ctx, frame)
	default:
		conn.send(encodeError(codeInvalidFrame, "unknown frame type", frame.Topic, 0))
	}
}

func (conn *connection) takeFrame(ctx context.Context) time.Duration {
	if conn.who.signedIn() {
		return conn.handler.limiter.TakeUser(ctx, ratelimit.BucketRelay, conn.who.clientID, conn.who.userID)
	}
	return conn.handler.limiter.TakeIP(ctx, ratelimit.BucketRelay, conn.who.ip)
}

func (conn *connection) topicIsValid(topic string) bool {
	if topic == "" || len(topic) > conn.handler.limits.MaxTopicBytes {
		conn.send(encodeError(codeInvalidTopic, "topic must be between 1 and the maximum topic bytes", topic, 0))
		return false
	}
	return true
}

func (conn *connection) subscribe(ctx context.Context, topic string) {
	if !conn.topicIsValid(topic) {
		return
	}
	if _, subscribed := conn.topics[topic]; subscribed {
		conn.send(encodeStatus(frameSubscribed, topic))
		return
	}
	if len(conn.topics) >= conn.handler.limits.MaxSubscriptions {
		conn.send(encodeError(codeSubscriptionLimit, "too many subscriptions on this connection", topic, 0))
		return
	}
	channel := channelName(conn.who.clientID, topic)
	conn.topics[topic] = channel
	if err := conn.handler.hub.Subscribe(ctx, conn, channel, topic); err != nil {
		delete(conn.topics, topic)
		slog.Warn("relay subscribe", "error", err)
		conn.send(encodeError(codeUnavailable, "relay is unavailable", topic, 0))
	}
}

func (conn *connection) unsubscribe(topic string) {
	channel, subscribed := conn.topics[topic]
	if subscribed {
		delete(conn.topics, topic)
		conn.handler.hub.Unsubscribe(conn, channel)
	}
	conn.send(encodeStatus(frameUnsubscribed, topic))
}

func (conn *connection) publish(ctx context.Context, frame clientFrame) {
	if !conn.topicIsValid(frame.Topic) {
		return
	}
	if len(frame.Data) > conn.handler.limits.MaxDataBytes {
		conn.send(encodeError(codeMessageTooLarge, "message data exceeds the maximum size", frame.Topic, 0))
		return
	}
	channel := channelName(conn.who.clientID, frame.Topic)
	if err := conn.handler.hub.Publish(ctx, channel, frame.Data); err != nil {
		slog.Warn("relay publish", "error", err)
		conn.send(encodeError(codeUnavailable, "relay is unavailable", frame.Topic, 0))
	}
}
