package gql

import "github.com/surrealdb/surrealdb.go/pkg/models"

const defaultMediaLimit = 200

// mediaRecordIDs maps media id strings to record ids for the album mutations.
func mediaRecordIDs(ids []string) []models.RecordID {
	out := make([]models.RecordID, len(ids))
	for i, id := range ids {
		out[i] = models.NewRecordID("media", id)
	}
	return out
}

// mediaPaging resolves optional limit/offset args to concrete values.
func mediaPaging(limit, offset *int) (int, int) {
	l := defaultMediaLimit
	if limit != nil {
		l = *limit
	}
	o := 0
	if offset != nil {
		o = *offset
	}
	return l, o
}
