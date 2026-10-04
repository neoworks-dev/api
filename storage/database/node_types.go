package database

import (
	"encoding/json"
	"time"

	"github.com/surrealdb/surrealdb.go/pkg/models"
)

type FacetContent struct {
	Facet      int    `json:"facet"`
	Ciphertext string `json:"ciphertext"`
}

// Node is one encrypted tree entry as clients see it. Everything the server
// stores is ciphertext, a wrapped key or a signature; none of it is interpreted.
type Node struct {
	ID            string          `json:"id"`
	ParentID      *string         `json:"parentId"`
	OwnerID       string          `json:"ownerId"`
	Collection    string          `json:"collection"`
	Kind          string          `json:"kind"`
	Epoch         int             `json:"epoch"`
	WrappedKey    *string         `json:"wrappedKey"`
	Content       []FacetContent  `json:"content"`
	Blob          json.RawMessage `json:"blob"`
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
	Content    []FacetContent  `json:"content"`
	Blob       json.RawMessage `json:"blob"`
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
	ID            *models.RecordID  `json:"id"`
	Owner         *models.RecordID  `json:"owner"`
	Parent        *models.RecordID  `json:"parent"`
	Ancestors     []models.RecordID `json:"ancestors"`
	Collection    string            `json:"collection"`
	Kind          string            `json:"kind"`
	Epoch         int               `json:"epoch"`
	WrappedKey    *string           `json:"wrapped_key"`
	Content       []FacetContent    `json:"content"`
	Blob          *string           `json:"blob"`
	BlobSize      int64             `json:"blob_size"`
	BlobObjects   []string          `json:"blob_objects"`
	Deleted       bool              `json:"deleted"`
	DeletedAt     *time.Time        `json:"deleted_at"`
	BaseSeq       int64             `json:"base_seq"`
	Seq           int64             `json:"seq"`
	AuthorType    string            `json:"author_type"`
	AuthorID      string            `json:"author_id"`
	CertID        *string           `json:"cert_id"`
	Signature     string            `json:"signature"`
	NeedsRotation bool              `json:"needs_rotation"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

func (row dbNode) toNode() Node {
	return Node{
		ID:            recordIDString(row.ID),
		ParentID:      optionalRecordID(row.Parent),
		OwnerID:       recordIDString(row.Owner),
		Collection:    row.Collection,
		Kind:          row.Kind,
		Epoch:         row.Epoch,
		WrappedKey:    row.WrappedKey,
		Content:       contentOrEmpty(row.Content),
		Blob:          rawBlob(row.Blob),
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
	Node       *models.RecordID `json:"node"`
	Parent     *models.RecordID `json:"parent"`
	Collection string           `json:"collection"`
	Kind       string           `json:"kind"`
	Epoch      int              `json:"epoch"`
	WrappedKey *string          `json:"wrapped_key"`
	Content    []FacetContent   `json:"content"`
	Blob       *string          `json:"blob"`
	Deleted    bool             `json:"deleted"`
	BaseSeq    int64            `json:"base_seq"`
	Seq        int64            `json:"seq"`
	AuthorType string           `json:"author_type"`
	AuthorID   string           `json:"author_id"`
	CertID     *string          `json:"cert_id"`
	Signature  string           `json:"signature"`
	CreatedAt  time.Time        `json:"created_at"`
}

func (row dbNodeVersion) toVersion() NodeVersion {
	return NodeVersion{
		NodeID:     recordIDString(row.Node),
		ParentID:   optionalRecordID(row.Parent),
		Collection: row.Collection,
		Kind:       row.Kind,
		Epoch:      row.Epoch,
		WrappedKey: row.WrappedKey,
		Content:    contentOrEmpty(row.Content),
		Blob:       rawBlob(row.Blob),
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
	Node          *models.RecordID `json:"node"`
	PrincipalType string           `json:"principal_type"`
	PrincipalID   string           `json:"principal_id"`
	Role          string           `json:"role"`
	Facets        []int            `json:"facets"`
	Epoch         int              `json:"epoch"`
	WrappedKeys   string           `json:"wrapped_keys"`
	GrantedByType string           `json:"granted_by_type"`
	GrantedByID   string           `json:"granted_by_id"`
	CertID        *string          `json:"cert_id"`
	Signature     string           `json:"signature"`
	Seq           int64            `json:"seq"`
	CreatedAt     time.Time        `json:"created_at"`
	RevokedAt     *time.Time       `json:"revoked_at"`
}

func (row dbAccessGrant) toGrant() AccessGrant {
	return AccessGrant{
		NodeID:        recordIDString(row.Node),
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
		CreatedAt:     row.CreatedAt,
		RevokedAt:     row.RevokedAt,
	}
}

func optionalRecordID(recordID *models.RecordID) *string {
	if recordID == nil {
		return nil
	}
	id := recordIDString(recordID)
	return &id
}

func contentOrEmpty(content []FacetContent) []FacetContent {
	if content == nil {
		return []FacetContent{}
	}
	return content
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
