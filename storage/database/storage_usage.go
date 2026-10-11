package database

import (
	"context"
	"fmt"
	"sort"

	"github.com/neoworks/auth/access"
)

// AppStorage is what one app stores in an account, and the cap the user set on it.
type AppStorage struct {
	ClientID  string `json:"clientId"`
	UsedBytes int64  `json:"usedBytes"`
	CapBytes  *int64 `json:"capBytes"`
}

// StorageUsage is an account's storage: its quota, what is used, and per app
// what each app stores inside that.
type StorageUsage struct {
	QuotaBytes int64        `json:"quotaBytes"`
	UsedBytes  int64        `json:"usedBytes"`
	Apps       []AppStorage `json:"apps"`
}

// QuotaError means a write would take the account or one app over its limit.
type QuotaError struct {
	// AppCap is true when the limit is the cap the user set on the app.
	AppCap     bool
	UsedBytes  int64
	LimitBytes int64
}

func (err *QuotaError) Error() string {
	if err.AppCap {
		return "app storage cap exceeded"
	}
	return "storage quota exceeded"
}

// StorageUsedBytes is what the owner's live nodes count against their quota:
// node content plus blob objects.
func (s *SurrealStore) StorageUsedBytes(ctx context.Context, ownerID string) (int64, error) {
	return s.sumStoredBytes(ctx, "owner_id = $owner_id", map[string]any{"owner_id": ownerID})
}

// AppStorageUsedBytes is the part of the owner's usage attributed to the app.
func (s *SurrealStore) AppStorageUsedBytes(ctx context.Context, ownerID string, clientID string) (int64, error) {
	return s.sumStoredBytes(ctx, "owner_id = $owner_id AND client_id = $client_id",
		map[string]any{"owner_id": ownerID, "client_id": clientID})
}

func (s *SurrealStore) sumStoredBytes(ctx context.Context, condition string, params map[string]any) (int64, error) {
	totals, err := queryRows[int64](ctx, s.DB,
		"SELECT VALUE math::sum(stored_bytes) FROM node WHERE "+condition+" GROUP ALL", params)
	if err != nil {
		return 0, fmt.Errorf("storage usage: %w", err)
	}
	if len(totals) == 0 {
		return 0, nil
	}
	return totals[0], nil
}

type dbAppUsage struct {
	ClientID *string `json:"client_id"`
	Used     int64   `json:"used"`
}

type dbAppCap struct {
	ClientID string `json:"client_id"`
	Cap      *int64 `json:"storage_cap_bytes"`
}

// GetStorageUsage reports the user's storage. Apps lists the clients the user
// authorized, with what each stores and its cap; a non-empty onlyClientID limits
// the list to that client, which is all an app may see of the account.
func (s *SurrealStore) GetStorageUsage(ctx context.Context, userID string, onlyClientID string) (*StorageUsage, error) {
	used, err := s.StorageUsedBytes(ctx, userID)
	if err != nil {
		return nil, err
	}
	apps, err := s.appStorage(ctx, userID, onlyClientID)
	if err != nil {
		return nil, err
	}
	return &StorageUsage{QuotaBytes: s.StorageQuotaBytes, UsedBytes: used, Apps: apps}, nil
}

func (s *SurrealStore) appStorage(ctx context.Context, userID string, onlyClientID string) ([]AppStorage, error) {
	usage, err := queryRows[dbAppUsage](ctx, s.DB,
		"SELECT client_id, math::sum(stored_bytes) AS used FROM node WHERE owner_id = $owner_id GROUP BY client_id",
		map[string]any{"owner_id": userID})
	if err != nil {
		return nil, fmt.Errorf("app storage usage: %w", err)
	}
	caps, err := queryRows[dbAppCap](ctx, s.DB,
		"SELECT record::id(client) AS client_id, storage_cap_bytes FROM grant WHERE user = $user AND enabled = true",
		map[string]any{"user": userRecord(userID)})
	if err != nil {
		return nil, fmt.Errorf("app storage caps: %w", err)
	}
	return mergeAppStorage(usage, caps, onlyClientID), nil
}

// mergeAppStorage lists every authorized client with its usage and cap, in
// client id order.
func mergeAppStorage(usage []dbAppUsage, caps []dbAppCap, onlyClientID string) []AppStorage {
	byClient := map[string]*AppStorage{}
	for _, entry := range caps {
		byClient[entry.ClientID] = &AppStorage{ClientID: entry.ClientID, CapBytes: entry.Cap}
	}
	for _, entry := range usage {
		if entry.ClientID != nil && byClient[*entry.ClientID] != nil {
			byClient[*entry.ClientID].UsedBytes = entry.Used
		}
	}
	apps := []AppStorage{}
	for clientID, app := range byClient {
		if onlyClientID == "" || onlyClientID == clientID {
			apps = append(apps, *app)
		}
	}
	sort.Slice(apps, func(first int, second int) bool { return apps[first].ClientID < apps[second].ClientID })
	return apps
}

// SetAppStorageCap sets or clears (nil) the cap the user puts on what an app
// may store in their account. ErrNotFound when the user never authorized the app.
func (s *SurrealStore) SetAppStorageCap(ctx context.Context, userID string, clientID string, capBytes *int64) error {
	statement := "UPDATE grant SET storage_cap_bytes = NONE WHERE user = $user AND client = $client"
	params := map[string]any{"user": userRecord(userID), "client": clientRecord(clientID)}
	if capBytes != nil {
		statement = "UPDATE grant SET storage_cap_bytes = $cap WHERE user = $user AND client = $client"
		params["cap"] = *capBytes
	}
	rows, err := queryRows[dbAppCap](ctx, s.DB, statement, params)
	if err != nil {
		return fmt.Errorf("set app storage cap: %w", err)
	}
	if len(rows) == 0 {
		return ErrNotFound
	}
	return nil
}

// batchGrowth is how many more bytes each owner would store once the batch is
// applied, ignoring nodes that shrink.
func (s *SurrealStore) batchGrowth(ctx context.Context, nodes []*ValidatedNode) (map[string]int64, error) {
	current, err := s.currentStoredBytes(ctx, nodes)
	if err != nil {
		return nil, err
	}
	growth := map[string]int64{}
	for _, validated := range nodes {
		change := StoredBytes(validated) - current[validated.Node.ID]
		if change > 0 {
			growth[validated.Node.OwnerID] += change
		}
	}
	return growth, nil
}

type dbStoredBytes struct {
	ID    string `json:"id"`
	Bytes int64  `json:"stored_bytes"`
}

func (s *SurrealStore) currentStoredBytes(ctx context.Context, nodes []*ValidatedNode) (map[string]int64, error) {
	ids := make([]string, 0, len(nodes))
	for _, validated := range nodes {
		ids = append(ids, validated.Node.ID)
	}
	rows, err := queryRows[dbStoredBytes](ctx, s.DB,
		"SELECT record::id(id) AS id, stored_bytes FROM node WHERE record::id(id) IN $ids", map[string]any{"ids": ids})
	if err != nil {
		return nil, fmt.Errorf("current stored bytes: %w", err)
	}
	current := make(map[string]int64, len(rows))
	for _, row := range rows {
		current[row.ID] = row.Bytes
	}
	return current, nil
}

// CheckPushQuota refuses a batch that would take an account, or one app inside
// it, over its limit before any node of the batch is written. The write of each
// node checks the limits again, so a concurrent push cannot slip past.
func (s *SurrealStore) CheckPushQuota(ctx context.Context, principal access.Principal, nodes []*ValidatedNode) error {
	growth, err := s.batchGrowth(ctx, nodes)
	if err != nil {
		return err
	}
	for ownerID, added := range growth {
		if err := s.checkOwnerGrowth(ctx, principal.ClientID, ownerID, added); err != nil {
			return err
		}
	}
	return nil
}

// CheckUploadAllowed refuses to hand out upload URLs while the owner is over
// their quota or the app is over its cap. The size of the blob is part of the
// usage by then: its node declared it when it was pushed.
func (s *SurrealStore) CheckUploadAllowed(ctx context.Context, principal access.Principal, ownerID string) error {
	return s.checkOwnerGrowth(ctx, principal.ClientID, ownerID, 0)
}

func (s *SurrealStore) checkOwnerGrowth(ctx context.Context, clientID string, ownerID string, added int64) error {
	used, err := s.StorageUsedBytes(ctx, ownerID)
	if err != nil {
		return err
	}
	if s.StorageQuotaBytes > 0 && used+added > s.StorageQuotaBytes {
		return &QuotaError{UsedBytes: used, LimitBytes: s.StorageQuotaBytes}
	}
	return s.checkAppGrowth(ctx, clientID, ownerID, added)
}

func (s *SurrealStore) checkAppGrowth(ctx context.Context, clientID string, ownerID string, added int64) error {
	if clientID == "" {
		return nil
	}
	capBytes, err := s.appStorageCap(ctx, ownerID, clientID)
	if err != nil || capBytes == nil {
		return err
	}
	used, err := s.AppStorageUsedBytes(ctx, ownerID, clientID)
	if err != nil {
		return err
	}
	if used+added > *capBytes {
		return &QuotaError{AppCap: true, UsedBytes: used, LimitBytes: *capBytes}
	}
	return nil
}

func (s *SurrealStore) appStorageCap(ctx context.Context, ownerID string, clientID string) (*int64, error) {
	rows, err := queryRows[dbAppCap](ctx, s.DB,
		"SELECT record::id(client) AS client_id, storage_cap_bytes FROM grant WHERE user = $user AND client = $client AND enabled = true",
		map[string]any{"user": userRecord(ownerID), "client": clientRecord(clientID)})
	if err != nil {
		return nil, fmt.Errorf("app storage cap: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return rows[0].Cap, nil
}

// QuotaFromOutcome turns a refused write into the error describing it.
func QuotaFromOutcome(outcome *PushOutcome) error {
	switch outcome.Status {
	case StatusQuotaExceeded:
		return &QuotaError{UsedBytes: outcome.UsedBytes, LimitBytes: outcome.LimitBytes}
	case StatusAppCapExceeded:
		return &QuotaError{AppCap: true, UsedBytes: outcome.UsedBytes, LimitBytes: outcome.LimitBytes}
	}
	return nil
}
