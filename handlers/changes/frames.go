package changes

import (
	"encoding/json"
	"strconv"
)

// Event names on the wire.
const (
	eventChange = "change"
	eventResync = "resync"
)

// Reasons a client is told to resync.
const (
	// reasonLost means the instance lost its live query and cannot say what changed.
	reasonLost = "lost"
	// reasonRestored means the live query is back; changes in between were missed.
	reasonRestored = "restored"
	// reasonMissed means the client's Last-Event-ID is behind changes it may see.
	reasonMissed = "missed"
)

// message is one event queued for a stream, before it is encoded.
type message struct {
	name       string
	collection string
	reason     string
	// seq is the sequence of the change, or the feed head for a resync that
	// knows it; zero means none.
	seq int64
}

func changeMessage(collection string, seq int64) message {
	return message{name: eventChange, collection: collection, seq: seq}
}

func resyncMessage(reason string) message {
	return message{name: eventResync, reason: reason}
}

func resyncMessageAt(reason string, head int64) message {
	return message{name: eventResync, reason: reason, seq: head}
}

type changeData struct {
	Collection string `json:"collection"`
	Seq        int64  `json:"seq"`
}

type resyncData struct {
	Reason string `json:"reason"`
	Seq    *int64 `json:"seq,omitempty"`
}

// encodeFrame renders the message as server-sent event text. highest is the
// largest sequence the stream has sent; a change that arrives late, with a lower
// sequence than one already sent, is sent as highest so the event ids a client
// keeps as Last-Event-ID never go backwards. A client pulls by one global
// cursor, so the later sequence covers the earlier change.
func encodeFrame(msg message, highest int64) ([]byte, int64) {
	if msg.name == eventChange {
		seq := max(msg.seq, highest)
		return eventFrame(eventChange, &seq, changeData{Collection: msg.collection, Seq: seq}), seq
	}
	if msg.seq == 0 {
		return eventFrame(eventResync, nil, resyncData{Reason: msg.reason}), highest
	}
	seq := max(msg.seq, highest)
	return eventFrame(eventResync, &seq, resyncData{Reason: msg.reason, Seq: &seq}), seq
}

func eventFrame(name string, id *int64, data any) []byte {
	encoded, _ := json.Marshal(data)
	frame := []byte{}
	if id != nil {
		frame = append(frame, "id: "+strconv.FormatInt(*id, 10)+"\n"...)
	}
	frame = append(frame, "event: "+name+"\ndata: "...)
	frame = append(frame, encoded...)
	return append(frame, "\n\n"...)
}

var (
	heartbeatFrame = []byte(": heartbeat\n\n")
	openingFrame   = []byte("retry: 3000\n\n: connected\n\n")
)
