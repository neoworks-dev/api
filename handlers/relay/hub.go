package relay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const reconnectDelay = time.Second

// channelState is one Redis channel with the local connections subscribed to it.
type channelState struct {
	topic       string
	subscribers map[*connection]struct{}
	// awaiting holds the connections still waiting for Redis to confirm the
	// subscription.
	awaiting  map[*connection]struct{}
	confirmed bool
}

// Hub connects the local connections of one API instance to Redis pub/sub, so
// a message published on one instance reaches subscribers on every instance.
// It holds one Redis subscription per channel that has a local subscriber.
type Hub struct {
	client *redis.Client
	pubsub *redis.PubSub
	cancel context.CancelFunc

	mutex    sync.Mutex
	channels map[string]*channelState
}

// NewHub starts delivering messages from Redis until Close is called.
func NewHub(client *redis.Client) *Hub {
	ctx, cancel := context.WithCancel(context.Background())
	hub := &Hub{client: client, pubsub: client.Subscribe(ctx), cancel: cancel, channels: map[string]*channelState{}}
	go hub.receive(ctx)
	return hub
}

func (hub *Hub) Close() {
	hub.cancel()
	_ = hub.pubsub.Close()
}

// channelName keeps client IDs apart: the length prefix stops a client "a" with
// topic "b:c" from colliding with a client "a:b" and topic "c".
func channelName(clientID string, topic string) string {
	return fmt.Sprintf("relay:%d:%s:%s", len(clientID), clientID, topic)
}

// Subscribe adds the connection to the channel and tells it "subscribed" once
// Redis confirms the subscription.
func (hub *Hub) Subscribe(ctx context.Context, subscriber *connection, channel string, topic string) error {
	hub.mutex.Lock()
	defer hub.mutex.Unlock()
	state, found := hub.channels[channel]
	if !found {
		if err := hub.pubsub.Subscribe(ctx, channel); err != nil {
			return err
		}
		state = &channelState{topic: topic, subscribers: map[*connection]struct{}{}, awaiting: map[*connection]struct{}{}}
		hub.channels[channel] = state
	}
	state.subscribers[subscriber] = struct{}{}
	if state.confirmed {
		subscriber.send(encodeStatus(frameSubscribed, topic))
		return nil
	}
	state.awaiting[subscriber] = struct{}{}
	return nil
}

// Unsubscribe removes the connection and drops the Redis subscription when no
// local connection is left on the channel.
func (hub *Hub) Unsubscribe(subscriber *connection, channel string) {
	hub.mutex.Lock()
	defer hub.mutex.Unlock()
	state, found := hub.channels[channel]
	if !found {
		return
	}
	delete(state.subscribers, subscriber)
	delete(state.awaiting, subscriber)
	if len(state.subscribers) > 0 {
		return
	}
	delete(hub.channels, channel)
	err := hub.pubsub.Unsubscribe(context.Background(), channel)
	if err != nil && !errors.Is(err, redis.ErrClosed) {
		slog.Warn("relay unsubscribe", "error", err)
	}
}

// Publish sends data to every subscriber of the channel on every instance.
func (hub *Hub) Publish(ctx context.Context, channel string, data string) error {
	return hub.client.Publish(ctx, channel, data).Err()
}

func (hub *Hub) receive(ctx context.Context) {
	for {
		received, err := hub.pubsub.Receive(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, redis.ErrClosed) {
				return
			}
			slog.Warn("relay redis receive", "error", err)
			time.Sleep(reconnectDelay)
			continue
		}
		switch event := received.(type) {
		case *redis.Subscription:
			if event.Kind == "subscribe" {
				hub.confirm(event.Channel)
			}
		case *redis.Message:
			hub.deliver(event.Channel, event.Payload)
		}
	}
}

func (hub *Hub) confirm(channel string) {
	hub.mutex.Lock()
	defer hub.mutex.Unlock()
	state, found := hub.channels[channel]
	if !found {
		return
	}
	state.confirmed = true
	for subscriber := range state.awaiting {
		subscriber.send(encodeStatus(frameSubscribed, state.topic))
	}
	state.awaiting = map[*connection]struct{}{}
}

func (hub *Hub) deliver(channel string, data string) {
	hub.mutex.Lock()
	defer hub.mutex.Unlock()
	state, found := hub.channels[channel]
	if !found {
		return
	}
	frame := encodeMessage(state.topic, data)
	for subscriber := range state.subscribers {
		subscriber.send(frame)
	}
}
