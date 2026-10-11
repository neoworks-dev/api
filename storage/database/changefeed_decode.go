package database

import (
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// decodeFeedChange reads the row of a live notification. It reports false when
// the row lacks the sequence or the node the change is about.
func decodeFeedChange(table string, result any) (FeedChange, bool) {
	row, isRow := result.(map[string]any)
	if !isRow {
		return FeedChange{}, false
	}
	change := FeedChange{
		Table:      table,
		Collection: stringValue(row["collection"]),
		OwnerID:    stringValue(row["owner_id"]),
	}
	seq, hasSeq := integerValue(row["seq"])
	change.Seq = seq
	if table == feedTableGrant {
		change.NodeID = stringValue(row["node_id"])
		change.Principal = FeedRecipient{Type: stringValue(row["principal_type"]), ID: stringValue(row["principal_id"])}
		change.GrantedBy = FeedRecipient{Type: stringValue(row["granted_by_type"]), ID: stringValue(row["granted_by_id"])}
	} else {
		change.NodeID = recordKey(row["id"])
		change.Ancestors = stringsValue(row["ancestors"])
	}
	return change, hasSeq && change.NodeID != ""
}

func recordKey(value any) string {
	switch record := value.(type) {
	case models.RecordID:
		return recordIDString(&record)
	case *models.RecordID:
		return recordIDString(record)
	}
	return ""
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func stringsValue(value any) []string {
	items, _ := value.([]any)
	texts := make([]string, 0, len(items))
	for _, item := range items {
		texts = append(texts, stringValue(item))
	}
	return texts
}

func integerValue(value any) (int64, bool) {
	switch number := value.(type) {
	case int64:
		return number, true
	case uint64:
		return int64(number), true
	case int:
		return int64(number), true
	case float64:
		return int64(number), true
	}
	return 0, false
}
