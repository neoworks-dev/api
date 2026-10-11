package ratelimit

import (
	"context"
	"sync"
	"time"
)

type memoryWindow struct {
	count   int64
	expires time.Time
}

// MemoryCounter counts in the memory of one process. The api uses it where no
// Redis is configured; limits then hold per instance only.
type MemoryCounter struct {
	mutex   sync.Mutex
	windows map[string]memoryWindow
	now     func() time.Time
}

func NewMemoryCounter() *MemoryCounter {
	return &MemoryCounter{windows: map[string]memoryWindow{}, now: time.Now}
}

func (counter *MemoryCounter) Hit(_ context.Context, key string, window time.Duration) (int64, time.Duration, error) {
	counter.mutex.Lock()
	defer counter.mutex.Unlock()
	current, running := counter.running(key)
	if !running {
		current = memoryWindow{expires: counter.now().Add(window)}
	}
	current.count++
	counter.windows[key] = current
	return current.count, current.expires.Sub(counter.now()), nil
}

func (counter *MemoryCounter) Peek(_ context.Context, key string) (int64, time.Duration, error) {
	counter.mutex.Lock()
	defer counter.mutex.Unlock()
	current, running := counter.running(key)
	if !running {
		return 0, 0, nil
	}
	return current.count, current.expires.Sub(counter.now()), nil
}

// running returns the key's window while it lasts, and forgets it afterwards.
// The mutex must be held.
func (counter *MemoryCounter) running(key string) (memoryWindow, bool) {
	current, found := counter.windows[key]
	if !found {
		return memoryWindow{}, false
	}
	if !counter.now().Before(current.expires) {
		delete(counter.windows, key)
		return memoryWindow{}, false
	}
	return current, true
}
