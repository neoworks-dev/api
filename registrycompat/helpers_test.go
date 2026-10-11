package registrycompat_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/neoworks/auth/registrycompat"
)

func number(text string) *json.Number {
	value := json.Number(text)
	return &value
}

func text(value string) *string {
	return &value
}

func scalarField(ordinal int, name, scalar string) registrycompat.Field {
	return registrycompat.Field{
		Ordinal: ordinal, Name: name, Required: true,
		Container: registrycompat.Container{Kind: "singular"},
		Value:     registrycompat.Shape{Kind: "scalar", Scalar: scalar},
	}
}

func optionalField(ordinal int, name, scalar string) registrycompat.Field {
	field := scalarField(ordinal, name, scalar)
	field.Required = false
	field.Container.Nullable = true
	return field
}

func listField(ordinal int, name, scalar string) registrycompat.Field {
	field := scalarField(ordinal, name, scalar)
	field.Required = false
	field.Container = registrycompat.Container{Kind: "repeatedLen"}
	return field
}

func enumField(ordinal int, name, enum string) registrycompat.Field {
	field := scalarField(ordinal, name, "")
	field.Value = registrycompat.Shape{Kind: "enum", Name: enum}
	return field
}

func oneofField(ordinal int, name string) registrycompat.Field {
	field := scalarField(ordinal, name, "")
	field.Value = registrycompat.Shape{Kind: "oneof", Variants: []registrycompat.OneofVariant{
		{Ordinal: 1, Name: "text", Value: registrycompat.Shape{Kind: "scalar", Scalar: "string"}},
		{Ordinal: 2, Name: "count", Value: registrycompat.Shape{Kind: "scalar", Scalar: "u32"}},
	}}
	return field
}

// baseDescriptor is a collection with one item model, an enum, a oneof and a
// second facet.
func baseDescriptor() *registrycompat.Descriptor {
	title := scalarField(1, "title", "string")
	title.Constraints = registrycompat.Constraints{MinLength: number("1"), MaxLength: number("200"), Format: text("slug")}
	score := optionalField(6, "score", "i64")
	score.Constraints = registrycompat.Constraints{MinValue: number("-9223372036854775808"), MaxValue: number("9223372036854775807")}
	return &registrycompat.Descriptor{
		Enums: []registrycompat.Enum{{Name: "Status", Variants: []registrycompat.EnumVariant{{Name: "open", Ordinal: 1}, {Name: "done", Ordinal: 2}}}},
		Models: []registrycompat.Model{{Name: "Task", Fields: []registrycompat.Field{
			title, optionalField(2, "note", "string"), listField(3, "tags", "string"),
			enumField(4, "status", "Status"), oneofField(5, "payload"), score,
		}}},
		Nodes: []registrycompat.Node{{Kind: "item", Model: "Task", Facets: []registrycompat.Facet{
			{Name: "default", Tag: 1, Fields: []int{1, 2, 3}},
			{Name: "Availability", Tag: 4242, Fields: []int{4, 5, 6}},
		}}},
	}
}

// clone copies a descriptor so a test can change it.
func clone(t *testing.T, descriptor *registrycompat.Descriptor) *registrycompat.Descriptor {
	t.Helper()
	encoded, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := registrycompat.Parse(string(encoded))
	if err != nil {
		t.Fatal(err)
	}
	return copied
}

func ruleNames(violations []registrycompat.Violation) []string {
	names := []string{}
	for _, violation := range violations {
		names = append(names, violation.Rule)
	}
	slices.Sort(names)
	return names
}

func checkAgainst(older, proposed *registrycompat.Descriptor) []registrycompat.Violation {
	return registrycompat.Check([]registrycompat.Version{{Version: "1.0.0", Descriptor: older}}, proposed)
}

func loadDescriptor(t *testing.T, name string) *registrycompat.Descriptor {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("testdata", name+".descriptor.json"))
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := registrycompat.Parse(string(contents))
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}
