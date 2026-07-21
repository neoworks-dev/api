package oauth

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// File JSON must expose record ids as bare strings, never the driver's
// {Table, ID} struct, which would leak the internal record shape to clients.
func TestFileMarshalJSONEmitsStringIDs(t *testing.T) {
	fileID := models.NewRecordID("file", "abc123")
	userID := models.NewRecordID("user", "u1")
	versionID := models.NewRecordID("file_version", "v1")
	chunkA := models.NewRecordID("chunk", "h1")
	chunkB := models.NewRecordID("chunk", "h2")

	m := File{
		ID:        &fileID,
		User:      &userID,
		Filename:  "chat-backup.bin",
		MimeType:  "application/octet-stream",
		Size:      42,
		Chunks:    []models.RecordID{chunkA, chunkB},
		Version:   &versionID,
		CreatedAt: time.Unix(0, 0).UTC(),
		UpdatedAt: time.Unix(0, 0).UTC(),
	}

	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got, ok := out["id"].(string); !ok || got != "abc123" {
		t.Fatalf("id = %v (%T), want bare string \"abc123\"", out["id"], out["id"])
	}
	if got, ok := out["user"].(string); !ok || got != "u1" {
		t.Fatalf("user = %v (%T), want \"u1\"", out["user"], out["user"])
	}
	if got, ok := out["version"].(string); !ok || got != "v1" {
		t.Fatalf("version = %v (%T), want \"v1\"", out["version"], out["version"])
	}

	chunks, ok := out["chunks"].([]any)
	if !ok || len(chunks) != 2 {
		t.Fatalf("chunks = %v, want 2 string elements", out["chunks"])
	}
	for i, want := range []string{"h1", "h2"} {
		if got, ok := chunks[i].(string); !ok || got != want {
			t.Fatalf("chunks[%d] = %v (%T), want %q", i, chunks[i], chunks[i], want)
		}
	}

	// Non-id fields still survive via the embedded alias.
	if out["filename"] != "chat-backup.bin" {
		t.Fatalf("filename = %v, want chat-backup.bin", out["filename"])
	}
}

// A nil id pointer must marshal away cleanly (omitempty) rather than panic or emit null.
func TestFileMarshalJSONNilIDs(t *testing.T) {
	raw, err := json.Marshal(File{Filename: "x"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := out["id"]; present {
		t.Fatalf("nil id should be omitted, got %v", out["id"])
	}
}

// Device and ApprovalRequest are written directly by REST handlers, so their id +
// user fields must also serialize as bare strings, not the {Table, ID} struct.
func TestDeviceMarshalJSONEmitsStringIDs(t *testing.T) {
	id := models.NewRecordID("device", "d1")
	user := models.NewRecordID("user", "u1")
	raw, err := json.Marshal(Device{ID: &id, User: &user, PublicKey: "pk"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out["id"] != "d1" || out["user"] != "u1" {
		t.Fatalf("id=%v user=%v, want bare strings d1/u1", out["id"], out["user"])
	}
	if out["public_key"] != "pk" {
		t.Fatalf("non-id field lost: public_key=%v", out["public_key"])
	}
}

func TestApprovalRequestMarshalJSONEmitsStringIDs(t *testing.T) {
	id := models.NewRecordID("approval_request", "a1")
	user := models.NewRecordID("user", "u1")
	raw, err := json.Marshal(ApprovalRequest{ID: &id, User: &user, Type: "signin", Status: "pending"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out["id"] != "a1" || out["user"] != "u1" {
		t.Fatalf("id=%v user=%v, want bare strings a1/u1", out["id"], out["user"])
	}
	if out["status"] != "pending" {
		t.Fatalf("non-id field lost: status=%v", out["status"])
	}
}
