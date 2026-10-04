package contactcodes

import (
	"sync"
	"time"
)

// windowCounter counts events per key inside a sliding window. State is in
// memory, so limits hold per api instance.
type windowCounter struct {
	mutex  sync.Mutex
	window time.Duration
	limit  int
	events map[string][]time.Time
	now    func() time.Time
}

func newWindowCounter(window time.Duration, limit int) *windowCounter {
	return &windowCounter{window: window, limit: limit, events: map[string][]time.Time{}, now: time.Now}
}

// prune drops expired events and returns the live ones. The mutex must be held.
func (counter *windowCounter) prune(key string) []time.Time {
	cutoff := counter.now().Add(-counter.window)
	live := counter.events[key][:0]
	for _, moment := range counter.events[key] {
		if moment.After(cutoff) {
			live = append(live, moment)
		}
	}
	if len(live) == 0 {
		delete(counter.events, key)
		return nil
	}
	counter.events[key] = live
	return live
}

// retryAfter is zero while the key is under its limit.
func (counter *windowCounter) retryAfter(key string) time.Duration {
	counter.mutex.Lock()
	defer counter.mutex.Unlock()
	live := counter.prune(key)
	if len(live) < counter.limit {
		return 0
	}
	return live[0].Add(counter.window).Sub(counter.now())
}

func (counter *windowCounter) record(key string) {
	counter.mutex.Lock()
	defer counter.mutex.Unlock()
	counter.prune(key)
	counter.events[key] = append(counter.events[key], counter.now())
}
