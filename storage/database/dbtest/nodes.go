package dbtest

import (
	"context"
	"testing"

	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/storage/database"
)

// NodeCollections are the collections whose node schemas every test database
// publishes, so tests can create roots in them.
var NodeCollections = []string{
	"@neoworks/calendar", "@neoworks/contacts", "@neoworks/photos", "@neoworks/files", "@neoworks/google",
}

// Content frames ciphertext as the default facet (tag 1) of a node's content,
// as clients do; the server only checks the framing.
func Content(ciphertext string) string {
	return encoding.EncodeToString(FacetField(1, []byte(ciphertext)))
}

// FacetField is one LEN field of node content: key tag*8+2, length, body.
func FacetField(tag int, body []byte) []byte {
	field := appendVarint(nil, uint64(tag)*8+2)
	field = appendVarint(field, uint64(len(body)))
	return append(field, body...)
}

func appendVarint(bytes []byte, value uint64) []byte {
	for value >= 0x80 {
		bytes = append(bytes, byte(value)|0x80)
		value >>= 7
	}
	return append(bytes, byte(value))
}

// PublishNodeSchemas publishes the schemas of NodeCollections unless the
// database has them already.
func PublishNodeSchemas(t *testing.T, store *database.SurrealStore) {
	t.Helper()
	scope, name, _ := access.ParseCollection(NodeCollections[0])
	if _, err := store.GetRegistrySchema(context.Background(), scope, name); err == nil {
		return
	}
	for _, collection := range NodeCollections {
		PublishNodeSchema(t, store, collection)
	}
}

// PublishNodeSchema publishes a version of the collection's schema with a node
// descriptor, from a publisher account of its own.
func PublishNodeSchema(t *testing.T, store *database.SurrealStore, collection string) {
	t.Helper()
	scope, name, ok := access.ParseCollection(collection)
	if !ok {
		t.Fatalf("not a collection: %s", collection)
	}
	publisher := CreateAccount(t, store)
	_, err := store.PublishRegistryVersion(context.Background(), publisher.Principal.UserID, database.RegistryPublishInput{
		Scope: scope, Name: name, Version: "1.0.0", Title: name, Description: "Test schema for " + collection,
		Files:      []database.RegistryPublishFile{{Path: name + ".schema", Contents: "namespace test"}},
		Descriptor: `{"descriptorVersion":1,"nodes":[]}`,
	})
	if err != nil {
		t.Fatalf("publish %s: %v", collection, err)
	}
}
