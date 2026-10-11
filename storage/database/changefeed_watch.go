package database

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/connection"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

const (
	feedTableNode  = "node"
	feedTableGrant = "access_grant"

	feedBuffer            = 1024
	defaultProbeInterval  = 10 * time.Second
	feedProbeTimeout      = 5 * time.Second
	feedConnectionTimeout = 10 * time.Second
)

// The live queries select only the columns the feed routes by, so node content
// and wrapped keys never leave the database for it.
const (
	nodeLiveStatement  = "LIVE SELECT id, owner_id, ancestors, collection, seq, target_id FROM node"
	grantLiveStatement = "LIVE SELECT id, node_id, collection, owner_id, principal_type, principal_id, " +
		"granted_by_type, granted_by_id, seq FROM access_grant"
)

// FeedWatch delivers the creations and updates of nodes and access grants from
// two live queries on a connection of its own. Live queries live and die with
// their connection and the driver does not close the notification channels
// when it drops, so a probe on that connection tells when the watch is lost.
type FeedWatch struct {
	db      *surrealdb.DB
	changes chan FeedChange
	lost    chan struct{}
	cancel  context.CancelFunc

	probeInterval time.Duration
	loseOnce      sync.Once
}

// WatchFeed starts the live queries. The caller ends the watch with Close and
// starts a new one after Lost is closed.
func (s *SurrealStore) WatchFeed(ctx context.Context) (*FeedWatch, error) {
	connectContext, cancelConnect := context.WithTimeout(ctx, feedConnectionTimeout)
	defer cancelConnect()
	db, err := s.dial(connectContext)
	if err != nil {
		return nil, fmt.Errorf("feed connection: %w", err)
	}
	watchContext, cancel := context.WithCancel(context.Background())
	watch := &FeedWatch{
		db: db, changes: make(chan FeedChange, feedBuffer), lost: make(chan struct{}), cancel: cancel,
		probeInterval: s.feedProbeInterval(),
	}
	for table, statement := range map[string]string{feedTableNode: nodeLiveStatement, feedTableGrant: grantLiveStatement} {
		if err := watch.start(connectContext, watchContext, table, statement); err != nil {
			watch.Close()
			return nil, err
		}
	}
	go watch.probe(watchContext)
	return watch, nil
}

func (watch *FeedWatch) start(connectContext context.Context, watchContext context.Context, table string, statement string) error {
	results, err := surrealdb.Query[models.UUID](connectContext, watch.db, statement, nil)
	if err != nil {
		return fmt.Errorf("live query on %s: %w", table, err)
	}
	notifications, err := watch.db.LiveNotifications((*results)[0].Result.String())
	if err != nil {
		return fmt.Errorf("live notifications on %s: %w", table, err)
	}
	go watch.forward(watchContext, table, notifications)
	return nil
}

// Changes carries every change in the order the database delivered it.
func (watch *FeedWatch) Changes() <-chan FeedChange {
	return watch.changes
}

// Lost is closed when the connection stopped answering.
func (watch *FeedWatch) Lost() <-chan struct{} {
	return watch.lost
}

func (watch *FeedWatch) Close() {
	watch.cancel()
	closeContext, cancel := context.WithTimeout(context.Background(), feedProbeTimeout)
	defer cancel()
	_ = watch.db.Close(closeContext)
}

// forward passes the notifications of one table on. A write that updates the
// same row twice at one sequence is delivered once, since pulling is by sequence.
func (watch *FeedWatch) forward(ctx context.Context, table string, notifications <-chan connection.Notification) {
	var previous FeedChange
	for {
		select {
		case <-ctx.Done():
			return
		case notification, open := <-notifications:
			if !open {
				watch.markLost()
				return
			}
			previous = watch.deliver(ctx, table, notification, previous)
		}
	}
}

func (watch *FeedWatch) deliver(ctx context.Context, table string, notification connection.Notification, previous FeedChange) FeedChange {
	if notification.Action == connection.DeleteAction {
		return previous
	}
	change, ok := decodeFeedChange(table, notification.Result)
	if !ok {
		slog.Warn("change feed notification not understood", "table", table)
		return previous
	}
	if change.sameRowAndSeq(previous) {
		return previous
	}
	select {
	case watch.changes <- change:
	case <-ctx.Done():
	}
	return change
}

func (watch *FeedWatch) probe(ctx context.Context) {
	ticker := time.NewTicker(watch.probeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := watch.ping(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("change feed connection lost", "error", err)
				watch.markLost()
				return
			}
		}
	}
}

func (watch *FeedWatch) ping(ctx context.Context) error {
	pingContext, cancel := context.WithTimeout(ctx, feedProbeTimeout)
	defer cancel()
	_, err := surrealdb.Query[bool](pingContext, watch.db, "RETURN true", nil)
	return err
}

func (watch *FeedWatch) markLost() {
	watch.loseOnce.Do(func() { close(watch.lost) })
}
