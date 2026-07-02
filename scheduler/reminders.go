// Package scheduler runs in-process background jobs for the API.
package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/neoworks/auth/push"
	"github.com/neoworks/auth/storage/database"
)

// maxLookAhead bounds how far in the future we scan for reminders, so a single
// tick never loads the entire calendar.
const maxLookAhead = 30 * 24 * time.Hour

// ReminderScheduler periodically fires calendar reminders as notifications to
// every member of the owning organization.
//
// Limitations (v1): recurring events are skipped (their occurrences are expanded
// client-side, not server-side). The fired-watermark is in-memory, so reminders
// due while the process is down are not replayed after a restart.
type ReminderScheduler struct {
	store    *database.SurrealStore
	pusher   push.Sender
	interval time.Duration
	lastRun  time.Time
}

func NewReminderScheduler(store *database.SurrealStore, pusher push.Sender) *ReminderScheduler {
	return &ReminderScheduler{
		store:    store,
		pusher:   pusher,
		interval: time.Minute,
	}
}

// Start launches the ticker loop in its own goroutine. It returns immediately;
// the loop stops when ctx is cancelled.
func (s *ReminderScheduler) Start(ctx context.Context) {
	s.lastRun = time.Now()
	go s.loop(ctx)
}

func (s *ReminderScheduler) loop(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := s.tick(ctx, now); err != nil {
				slog.Error("reminder tick", "err", err)
			}
			s.lastRun = now
		}
	}
}

// tick fires every reminder whose computed fire time (start_time - offset) lands
// in the window (lastRun, now].
func (s *ReminderScheduler) tick(ctx context.Context, now time.Time) error {
	candidates, err := s.store.ListReminderCandidates(ctx, s.lastRun, now.Add(maxLookAhead))
	if err != nil {
		return err
	}
	for _, c := range candidates {
		for _, offset := range c.Reminders {
			fireAt := c.StartTime.Add(-time.Duration(offset) * time.Minute)
			if fireAt.After(s.lastRun) && !fireAt.After(now) {
				s.fire(ctx, c, offset)
			}
		}
	}
	return nil
}

func (s *ReminderScheduler) fire(ctx context.Context, c database.ReminderCandidate, offset int) {
	members, err := s.store.ListOrgMemberIDs(ctx, c.Org)
	if err != nil {
		slog.Error("reminder members", "event", c.ID, "err", err)
		return
	}
	body := reminderBody(c.StartTime, offset)
	for _, userID := range members {
		id, err := s.store.CreateNotification(ctx, userID, c.Title, body, nil)
		if err != nil {
			slog.Error("reminder notification", "user", userID, "event", c.ID, "err", err)
			continue
		}
		s.deliver(ctx, userID, c.Title, body, id)
	}
}

// deliver is best-effort device push; a failure never blocks other recipients.
func (s *ReminderScheduler) deliver(ctx context.Context, userID, title, body, notificationID string) {
	tokens, err := s.store.ListPushTokensForUser(ctx, userID)
	if err != nil || len(tokens) == 0 {
		return
	}
	data := map[string]string{"type": "notification"}
	if notificationID != "" {
		data["notification_id"] = notificationID
	}
	_ = s.pusher.Send(ctx, tokens, title, body, data)
}

func reminderBody(start time.Time, offset int) string {
	if offset <= 0 {
		return "Starting now"
	}
	when := start.Format("15:04")
	if offset%60 == 0 {
		return fmt.Sprintf("Starts in %dh (at %s)", offset/60, when)
	}
	return fmt.Sprintf("Starts in %dm (at %s)", offset, when)
}
