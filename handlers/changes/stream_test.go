package changes

import (
	"testing"

	"github.com/neoworks/auth/access"
)

func TestStreamThatCannotKeepUpIsClosedInsteadOfBlockingTheFeed(t *testing.T) {
	slow := newStream(access.Principal{UserID: "owner"}, 2)

	slow.send(changeMessage("@neoworks/photos", 1))
	slow.send(changeMessage("@neoworks/photos", 2))
	select {
	case <-slow.done:
		t.Fatal("a stream within its buffer stays open")
	default:
	}
	slow.send(changeMessage("@neoworks/photos", 3))

	select {
	case <-slow.done:
	default:
		t.Fatal("a stream past its buffer should be closed")
	}
}
