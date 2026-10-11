package changes

import (
	"sync"

	"github.com/neoworks/auth/access"
)

// stream is one open connection of a client.
type stream struct {
	principal access.Principal
	messages  chan message
	done      chan struct{}
	closing   sync.Once
}

func newStream(principal access.Principal, buffer int) *stream {
	return &stream{principal: principal, messages: make(chan message, buffer), done: make(chan struct{})}
}

// send queues a message without blocking. A stream that cannot keep up is closed
// instead of holding back the feed; its client reconnects with Last-Event-ID
// and is told to resync if it missed something.
func (open *stream) send(msg message) {
	select {
	case open.messages <- msg:
	default:
		open.close()
	}
}

func (open *stream) close() {
	open.closing.Do(func() { close(open.done) })
}
