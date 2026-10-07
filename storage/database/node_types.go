package database

import (
	"encoding/json"
	"time"

	"github.com/neoworks/auth/accesslog"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// Node is one encrypted tree entry as clients see it. Everything the server
// stores is ciphertext, a wrapped key or a signature; none of it is decrypted.
// Content is base64url of one message holding a LEN field per facet tag whose
// body is that facet's ciphertext. A shortcut names its target item and the
// highest role it passes on, and carries no content or blob.
type Node struct {
	ID            string          `json:"id"`
	ParentID      *string         `json:"parentId"`
	OwnerID       string          `json:"ownerId"`
	Collection    string          `json:"collection"`
	Kind          string          `json:"kind"`
	Epoch         int             `json:"epoch"`
	WrappedKey    *string         `json:"wrappedKey"`
	Content       string          `json:"content"`
	Blob          json.RawMessage `json:"blob"`
	TargetID      *string         `json:"targetId"`
	TargetRole    *string         `json:"targetRole"`
	Deleted       bool            `json:"deleted"`
	BaseSeq       int64           `json:"baseSeq"`
	Seq           int64           `json:"seq"`
	AuthorType    string          `json:"authorType"`
	AuthorID      string          `json:"authorId"`
	CertID        *string         `json:"certId"`
	Signature     string          `json:"signature"`
	NeedsRotation bool            `json:"needsRotation"`
	CreatedAt     time.Time       `json:"createdAt"`
	UpdatedAt     time.Time       `json:"updatedAt"`
}

// IsShortcut reports whether the node stands for another item.
func (node Node) IsShortcut() bool {
	return node.TargetID != nil
}

// AccessGrant is one principal's access to a node together with the key
// material sealed to that principal.
type AccessGrant struct {
	NodeID        string     `json:"nodeId"`
	PrincipalType string     `json:"principalType"`
	PrincipalID   string     `json:"principalId"`
	Role          string     `json:"role"`
	Facets        []int      `json:"facets"`
	Epoch         int        `json:"epoch"`
	WrappedKeys   string     `json:"wrappedKeys"`
	GrantedByType string     `json:"grantedByType"`
	GrantedByID   string     `json:"grantedById"`
	CertID        *string    `json:"certId"`
	Signature     string     `json:"signature"`
	Seq           int64      `json:"seq"`
	LogIndex      int64      `json:"logIndex"`
	CreatedAt     time.Time  `json:"createdAt"`
	RevokedAt     *time.Time `json:"revokedAt"`
}

// NodeVersion is one entry of a node's history: everything the write signature
// covers, so a past version verifies on its own.
type NodeVersion struct {
	NodeID     string          `json:"nodeId"`
	ParentID   *string         `json:"parentId"`
	Collection string          `json:"collection"`
	Kind       string          `json:"kind"`
	Epoch      int             `json:"epoch"`
	WrappedKey *string         `json:"wrappedKey"`
	Content    string          `json:"content"`
	Blob       json.RawMessage `json:"blob"`
	TargetID   *string         `json:"targetId"`
	TargetRole *string         `json:"targetRole"`
	Deleted    bool            `json:"deleted"`
	BaseSeq    int64           `json:"baseSeq"`
	Seq        int64           `json:"seq"`
	AuthorType string          `json:"authorType"`
	AuthorID   string          `json:"authorId"`
	CertID     *string         `json:"certId"`
	Signature  string          `json:"signature"`
	CreatedAt  time.Time       `json:"createdAt"`
}

type dbNode struct {
	ID            *models.RecordID `json:"id"`
	OwnerID       string           `json:"owner_id"`
	ParentID      *string          `json:"parent_id"`
	Ancestors     []string         `json:"ancestors"`
	Collection    string           `json:"collection"`
	Kind          string           `json:"kind"`
	Epoch         int              `json:"epoch"`
	WrappedKey    *string          `json:"wrapped_key"`
	Content       string           `json:"content"`
	BlobJSON      *string          `json:"blob_json"`
	BlobSize      int64            `json:"blob_size"`
	BlobObjects   []string         `json:"blob_objects"`
	TargetID      *string          `json:"target_id"`
	TargetRole    *string          `json:"target_role"`
	Deleted       bool             `json:"deleted"`
	DeletedAt     *time.Time       `json:"deleted_at"`
	BaseSeq       int64            `json:"base_seq"`
	Seq           int64            `json:"seq"`
	AuthorType    string           `json:"author_type"`
	AuthorID      string           `json:"author_id"`
	CertID        *string          `json:"cert_id"`
	Signature     string           `json:"signature"`
	NeedsRotation bool             `json:"needs_rotation"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
}

func (row dbNode) toNode() Node {
	return Node{
		ID:            recordIDString(row.ID),
		ParentID:      row.ParentID,
		OwnerID:       row.OwnerID,
		Collection:    row.Collection,
		Kind:          row.Kind,
		Epoch:         row.Epoch,
		WrappedKey:    row.WrappedKey,
		Content:       row.Content,
		Blob:          rawBlob(row.BlobJSON),
		TargetID:      row.TargetID,
		TargetRole:    row.TargetRole,
		Deleted:       row.Deleted,
		BaseSeq:       row.BaseSeq,
		Seq:           row.Seq,
		AuthorType:    row.AuthorType,
		AuthorID:      row.AuthorID,
		CertID:        row.CertID,
		Signature:     row.Signature,
		NeedsRotation: row.NeedsRotation,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}
}

type dbNodeVersion struct {
	NodeID     string    `json:"node_id"`
	ParentID   *string   `json:"parent_id"`
	Collection string    `json:"collection"`
	Kind       string    `json:"kind"`
	Epoch      int       `json:"epoch"`
	WrappedKey *string   `json:"wrapped_key"`
	Content    string    `json:"content"`
	BlobJSON   *string   `json:"blob_json"`
	TargetID   *string   `json:"target_id"`
	TargetRole *string   `json:"target_role"`
	Deleted    bool      `json:"deleted"`
	BaseSeq    int64     `json:"base_seq"`
	Seq        int64     `json:"seq"`
	AuthorType string    `json:"author_type"`
	AuthorID   string    `json:"author_id"`
	CertID     *string   `json:"cert_id"`
	Signature  string    `json:"signature"`
	CreatedAt  time.Time `json:"created_at"`
}

func (row dbNodeVersion) toVersion() NodeVersion {
	return NodeVersion{
		NodeID:     row.NodeID,
		ParentID:   row.ParentID,
		Collection: row.Collection,
		Kind:       row.Kind,
		Epoch:      row.Epoch,
		WrappedKey: row.WrappedKey,
		Content:    row.Content,
		Blob:       rawBlob(row.BlobJSON),
		TargetID:   row.TargetID,
		TargetRole: row.TargetRole,
		Deleted:    row.Deleted,
		BaseSeq:    row.BaseSeq,
		Seq:        row.Seq,
		AuthorType: row.AuthorType,
		AuthorID:   row.AuthorID,
		CertID:     row.CertID,
		Signature:  row.Signature,
		CreatedAt:  row.CreatedAt,
	}
}

type dbAccessGrant struct {
	NodeID        string     `json:"node_id"`
	PrincipalType string     `json:"principal_type"`
	PrincipalID   string     `json:"principal_id"`
	Role          string     `json:"role"`
	Facets        []int      `json:"facets"`
	Epoch         int        `json:"epoch"`
	WrappedKeys   string     `json:"wrapped_keys"`
	GrantedByType string     `json:"granted_by_type"`
	GrantedByID   string     `json:"granted_by_id"`
	CertID        *string    `json:"cert_id"`
	Signature     string     `json:"signature"`
	Seq           int64      `json:"seq"`
	LogIndex      int64      `json:"log_index"`
	CreatedAt     time.Time  `json:"created_at"`
	RevokedAt     *time.Time `json:"revoked_at"`
}

func (row dbAccessGrant) toGrant() AccessGrant {
	return AccessGrant{
		NodeID:        row.NodeID,
		PrincipalType: row.PrincipalType,
		PrincipalID:   row.PrincipalID,
		Role:          row.Role,
		Facets:        row.Facets,
		Epoch:         row.Epoch,
		WrappedKeys:   row.WrappedKeys,
		GrantedByType: row.GrantedByType,
		GrantedByID:   row.GrantedByID,
		CertID:        row.CertID,
		Signature:     row.Signature,
		Seq:           row.Seq,
		LogIndex:      row.LogIndex,
		CreatedAt:     row.CreatedAt,
		RevokedAt:     row.RevokedAt,
	}
}

func rawBlob(blob *string) json.RawMessage {
	if blob == nil {
		return nil
	}
	return json.RawMessage(*blob)
}

func nodesFromRows(rows []dbNode) []Node {
	nodes := make([]Node, 0, len(rows))
	for _, row := range rows {
		nodes = append(nodes, row.toNode())
	}
	return nodes
}

func grantsFromRows(rows []dbAccessGrant) []AccessGrant {
	grants := make([]AccessGrant, 0, len(rows))
	for _, row := range rows {
		grants = append(grants, row.toGrant())
	}
	return grants
}

type dbAccessLog struct {
	NodeID          string  `json:"node_id"`
	Index           int64   `json:"index"`
	PrevHash        string  `json:"prev_hash"`
	EntryHash       string  `json:"entry_hash"`
	Action          string  `json:"action"`
	PrincipalType   string  `json:"principal_type"`
	PrincipalID     string  `json:"principal_id"`
	Role            string  `json:"role"`
	Facets          []int   `json:"facets"`
	Epoch           int     `json:"epoch"`
	WrappedKeysHash string  `json:"wrapped_keys_hash"`
	ActorType       string  `json:"actor_type"`
	ActorID         string  `json:"actor_id"`
	CertID          *string `json:"cert_id"`
	Signature       string  `json:"signature"`
	Seq             int64   `json:"seq"`
}

func (row dbAccessLog) toEntry() accesslog.Entry {
	return accesslog.Entry{
		NodeID:          row.NodeID,
		Index:           row.Index,
		PrevHash:        row.PrevHash,
		Action:          row.Action,
		PrincipalType:   row.PrincipalType,
		PrincipalID:     row.PrincipalID,
		Role:            row.Role,
		Facets:          row.Facets,
		Epoch:           row.Epoch,
		WrappedKeysHash: row.WrappedKeysHash,
		ActorType:       row.ActorType,
		ActorID:         row.ActorID,
		CertID:          row.CertID,
		Signature:       row.Signature,
		EntryHash:       row.EntryHash,
	}
}

func logFromRows(rows []dbAccessLog) []accesslog.Entry {
	entries := make([]accesslog.Entry, 0, len(rows))
	for _, row := range rows {
		entries = append(entries, row.toEntry())
	}
	return entries
}
