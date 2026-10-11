package registrycompat_test

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/neoworks/auth/registrycompat"
)

var neoworksCollections = []string{"neoworks-calendar", "neoworks-contacts", "neoworks-google", "neoworks-photos"}

func TestEveryPublishedNeoworksCollectionIsCompatibleWithItself(t *testing.T) {
	collections := append(slices.Clone(neoworksCollections), "example-songs")
	for _, collection := range collections {
		t.Run(collection, func(t *testing.T) {
			descriptor := loadDescriptor(t, collection)
			if violations := checkAgainst(descriptor, loadDescriptor(t, collection)); len(violations) != 0 {
				t.Fatalf("unexpected violations: %+v", violations)
			}
		})
	}
}

// grown adds an optional field to the first model and its default facet.
func grown(descriptor *registrycompat.Descriptor) {
	model := &descriptor.Models[0]
	highest := 0
	for _, field := range model.Fields {
		highest = max(highest, field.Ordinal)
	}
	model.Fields = append(model.Fields, optionalField(highest+1, "addedLater", "string"))
	for index := range descriptor.Nodes {
		if descriptor.Nodes[index].Model == model.Name {
			descriptor.Nodes[index].Facets[0].Fields = append(descriptor.Nodes[index].Facets[0].Fields, highest+1)
		}
	}
}

func TestNeoworksCollectionsMayGrowAnOptionalField(t *testing.T) {
	for _, collection := range neoworksCollections {
		t.Run(collection, func(t *testing.T) {
			proposed := loadDescriptor(t, collection)
			grown(proposed)
			if violations := checkAgainst(loadDescriptor(t, collection), proposed); len(violations) != 0 {
				t.Fatalf("unexpected violations: %+v", violations)
			}
		})
	}
}

func TestNeoworksCollectionsRefuseReusingANumberForAnotherName(t *testing.T) {
	for _, collection := range neoworksCollections {
		t.Run(collection, func(t *testing.T) {
			proposed := loadDescriptor(t, collection)
			proposed.Models[0].Fields[0].Name += "Renamed"
			violations := checkAgainst(loadDescriptor(t, collection), proposed)
			if !slices.Equal(ruleNames(violations), []string{registrycompat.RuleFieldOrdinalReused}) {
				t.Fatalf("unexpected violations: %+v", violations)
			}
		})
	}
}

// songsVersion010 is @example/songs 0.1.0: the library of songs without the
// playlist container that 0.2.0 added.
func songsVersion010(t *testing.T) *registrycompat.Descriptor {
	t.Helper()
	descriptor := loadDescriptor(t, "example-songs")
	descriptor.Models = slices.DeleteFunc(descriptor.Models, func(model registrycompat.Model) bool { return model.Name == "Playlist" })
	descriptor.Nodes = slices.DeleteFunc(descriptor.Nodes, func(node registrycompat.Node) bool { return node.Kind == "container" })
	return descriptor
}

func TestSongsHistoryIsCompatible(t *testing.T) {
	published := []registrycompat.Version{{Version: "0.1.0", Descriptor: songsVersion010(t)}}
	if violations := registrycompat.Check(published, loadDescriptor(t, "example-songs")); len(violations) != 0 {
		t.Fatalf("0.2.0 must follow 0.1.0: %+v", violations)
	}
}

func TestDroppingThePlaylistContainerAgainIsRefused(t *testing.T) {
	published := []registrycompat.Version{
		{Version: "0.1.0", Descriptor: songsVersion010(t)},
		{Version: "0.2.0", Descriptor: loadDescriptor(t, "example-songs")},
	}
	violations := registrycompat.Check(published, songsVersion010(t))
	if !slices.Equal(ruleNames(violations), []string{registrycompat.RuleNodeKindRemoved}) {
		t.Fatalf("unexpected violations: %+v", violations)
	}
	if violations[0].Path != "nodes.container" {
		t.Fatalf("unexpected path: %+v", violations[0])
	}
}

func TestANumberOfARemovedFieldCannotComeBack(t *testing.T) {
	first := baseDescriptor()
	taskModel(first).Fields = append(taskModel(first).Fields, optionalField(8, "legacy", "string"))
	second := clone(t, baseDescriptor())
	third := clone(t, baseDescriptor())
	taskModel(third).Fields = append(taskModel(third).Fields, optionalField(8, "dueDate", "timestamp"))

	published := []registrycompat.Version{{Version: "1.0.0", Descriptor: first}, {Version: "1.1.0", Descriptor: second}}
	violations := registrycompat.Check(published, third)
	if len(violations) != 1 || violations[0].Rule != registrycompat.RuleFieldOrdinalReused {
		t.Fatalf("unexpected violations: %+v", violations)
	}
	if lastOnly := registrycompat.Check(published[1:], third); len(lastOnly) != 0 {
		t.Fatalf("only the older version remembers the number: %+v", lastOnly)
	}
}

func TestVersionsWithoutADescriptorAreSkipped(t *testing.T) {
	published := []registrycompat.Version{{Version: "0.0.1"}, {Version: "1.0.0", Descriptor: baseDescriptor()}}
	if violations := registrycompat.Check(published, clone(t, baseDescriptor())); len(violations) != 0 {
		t.Fatalf("unexpected violations: %+v", violations)
	}
}

// TestTestdataMatchesTheMonorepo notices when a schema in the monorepo moves on
// without these copies.
func TestTestdataMatchesTheMonorepo(t *testing.T) {
	sources := map[string]string{
		"example-songs":     "apps/songs/schema/generated/schema.descriptor.json",
		"neoworks-calendar": "packages/schemas/calendar/generated/schema.descriptor.json",
		"neoworks-contacts": "packages/schemas/contacts/generated/schema.descriptor.json",
		"neoworks-google":   "packages/schemas/google/generated/schema.descriptor.json",
		"neoworks-photos":   "packages/schemas/photos/generated/schema.descriptor.json",
	}
	for name, source := range sources {
		original, err := os.ReadFile(filepath.Join("..", "..", "..", source))
		if err != nil {
			t.Skip("not inside the monorepo")
		}
		copied, err := os.ReadFile(filepath.Join("testdata", name+".descriptor.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(original, copied) {
			t.Errorf("testdata/%s.descriptor.json differs from %s; copy it again", name, source)
		}
	}
}
