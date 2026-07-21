package gql

import "github.com/surrealdb/surrealdb.go/pkg/models"

const defaultFileLimit = 200

// fileRecordIDs maps file id strings to record ids for the album mutations.
func fileRecordIDs(ids []string) []models.RecordID {
	out := make([]models.RecordID, len(ids))
	for i, id := range ids {
		out[i] = models.NewRecordID("file", id)
	}
	return out
}

// filePaging resolves optional limit/offset args to concrete values.
func filePaging(limit, offset *int) (int, int) {
	l := defaultFileLimit
	if limit != nil {
		l = *limit
	}
	o := 0
	if offset != nil {
		o = *offset
	}
	return l, o
}
