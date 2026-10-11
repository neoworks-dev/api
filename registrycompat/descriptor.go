// Package registrycompat decides whether a schema version published to the
// registry stays compatible with the versions published before it. Every app
// holding a collection's scope reads and writes the same encrypted nodes, so a
// new version must keep reading what older versions wrote and the other way
// round. It works on the descriptor JSON, which carries the ordinals and types.
package registrycompat

import (
	"encoding/json"
	"fmt"
)

// Descriptor is the part of a schema descriptor the compatibility rules read.
type Descriptor struct {
	Enums  []Enum  `json:"enums"`
	Models []Model `json:"models"`
	Nodes  []Node  `json:"nodes"`
}

type Enum struct {
	Name     string        `json:"name"`
	Variants []EnumVariant `json:"variants"`
}

type EnumVariant struct {
	Name    string `json:"name"`
	Ordinal int    `json:"ordinal"`
}

type Model struct {
	Name   string  `json:"name"`
	Fields []Field `json:"fields"`
}

type Field struct {
	Ordinal     int         `json:"ordinal"`
	Name        string      `json:"name"`
	Container   Container   `json:"container"`
	Value       Shape       `json:"value"`
	Required    bool        `json:"required"`
	Constraints Constraints `json:"constraints"`
}

// Container is the wire layout around a value: singular, list or map, and
// whether the field may be absent.
type Container struct {
	Kind     string `json:"kind"`
	Nullable bool   `json:"nullable"`
	Key      string `json:"key"`
}

// Shape is the type of a value.
type Shape struct {
	Kind      string         `json:"kind"`
	Scalar    string         `json:"scalar"`
	Name      string         `json:"name"`
	Precision int            `json:"precision"`
	Scale     int            `json:"scale"`
	Variants  []OneofVariant `json:"variants"`
}

type OneofVariant struct {
	Ordinal int    `json:"ordinal"`
	Name    string `json:"name"`
	Value   Shape  `json:"value"`
}

// Constraints are the value constraints a runtime enforces. Numbers stay
// json.Number so large integer bounds compare exactly.
type Constraints struct {
	MinValue  *json.Number `json:"minValue"`
	MaxValue  *json.Number `json:"maxValue"`
	MinLength *json.Number `json:"minLength"`
	MaxLength *json.Number `json:"maxLength"`
	Pattern   *string      `json:"pattern"`
	Format    *string      `json:"format"`
}

// Node maps a node kind (container or item) to the model stored as its content.
type Node struct {
	Kind   string  `json:"kind"`
	Model  string  `json:"model"`
	Facets []Facet `json:"facets"`
}

// Facet is a separately encrypted group of a node model's fields.
type Facet struct {
	Name   string `json:"name"`
	Tag    int    `json:"tag"`
	Fields []int  `json:"fields"`
}

// Parse reads a descriptor. An empty text is the descriptor of a schema that
// defines no nodes.
func Parse(text string) (*Descriptor, error) {
	if text == "" {
		return &Descriptor{}, nil
	}
	var descriptor Descriptor
	if err := json.Unmarshal([]byte(text), &descriptor); err != nil {
		return nil, fmt.Errorf("descriptor does not have the expected shape: %w", err)
	}
	return &descriptor, nil
}

// category is singular, list or map, whatever the wire layout of the list or map.
func (container Container) category() string {
	switch container.Kind {
	case "repeatedPacked", "repeatedLen", "wrapperRepeated":
		return "list"
	case "map", "wrapperMap":
		return "map"
	default:
		return container.Kind
	}
}

// nullable reports whether the field may be absent.
func (container Container) nullable() bool {
	switch container.Kind {
	case "singular":
		return container.Nullable
	case "wrapperRepeated", "wrapperMap":
		return true
	default:
		return false
	}
}

func (model Model) field(ordinal int) (Field, bool) {
	for _, field := range model.Fields {
		if field.Ordinal == ordinal {
			return field, true
		}
	}
	return Field{}, false
}

func (descriptor *Descriptor) model(name string) (Model, bool) {
	for _, model := range descriptor.Models {
		if model.Name == name {
			return model, true
		}
	}
	return Model{}, false
}

func (descriptor *Descriptor) enum(name string) (Enum, bool) {
	for _, enum := range descriptor.Enums {
		if enum.Name == name {
			return enum, true
		}
	}
	return Enum{}, false
}

func (descriptor *Descriptor) node(kind string) (Node, bool) {
	for _, node := range descriptor.Nodes {
		if node.Kind == kind {
			return node, true
		}
	}
	return Node{}, false
}
