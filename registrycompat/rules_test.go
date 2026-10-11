package registrycompat_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/neoworks/auth/registrycompat"
)

func taskModel(descriptor *registrycompat.Descriptor) *registrycompat.Model {
	return &descriptor.Models[0]
}

func TestAnUnchangedDescriptorIsCompatible(t *testing.T) {
	base := baseDescriptor()
	if violations := checkAgainst(base, clone(t, base)); len(violations) != 0 {
		t.Fatalf("unexpected violations: %+v", violations)
	}
}

func TestCompatibleChangesPass(t *testing.T) {
	cases := map[string]func(descriptor *registrycompat.Descriptor){
		"a new optional field": func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields = append(taskModel(descriptor).Fields, optionalField(7, "due", "timestamp"))
		},
		"a new list field": func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields = append(taskModel(descriptor).Fields, listField(7, "labels", "string"))
		},
		"a new enum variant": func(descriptor *registrycompat.Descriptor) {
			descriptor.Enums[0].Variants = append(descriptor.Enums[0].Variants, registrycompat.EnumVariant{Name: "blocked", Ordinal: 3})
		},
		"a new oneof variant": func(descriptor *registrycompat.Descriptor) {
			variants := &taskModel(descriptor).Fields[4].Value.Variants
			*variants = append(*variants, registrycompat.OneofVariant{Ordinal: 3, Name: "flag", Value: registrycompat.Shape{Kind: "scalar", Scalar: "bool"}})
		},
		"a new model with required fields": func(descriptor *registrycompat.Descriptor) {
			descriptor.Models = append(descriptor.Models, registrycompat.Model{Name: "Folder", Fields: []registrycompat.Field{scalarField(1, "name", "string")}})
		},
		"a new node kind": func(descriptor *registrycompat.Descriptor) {
			descriptor.Models = append(descriptor.Models, registrycompat.Model{Name: "Folder", Fields: []registrycompat.Field{scalarField(1, "name", "string")}})
			descriptor.Nodes = append(descriptor.Nodes, registrycompat.Node{Kind: "container", Model: "Folder",
				Facets: []registrycompat.Facet{{Name: "default", Tag: 1, Fields: []int{1}}}})
		},
		"a new field in an existing facet": func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields = append(taskModel(descriptor).Fields, optionalField(7, "due", "timestamp"))
			descriptor.Nodes[0].Facets[1].Fields = append(descriptor.Nodes[0].Facets[1].Fields, 7)
		},
		"a new facet for new fields": func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields = append(taskModel(descriptor).Fields, optionalField(7, "due", "timestamp"))
			descriptor.Nodes[0].Facets = append(descriptor.Nodes[0].Facets, registrycompat.Facet{Name: "Schedule", Tag: 777, Fields: []int{7}})
		},
		"a removed field": func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields = taskModel(descriptor).Fields[:5]
			descriptor.Nodes[0].Facets[1].Fields = []int{4, 5}
		},
		"looser bounds": func(descriptor *registrycompat.Descriptor) {
			constraints := &taskModel(descriptor).Fields[0].Constraints
			constraints.MinLength = nil
			constraints.MaxLength = number("500")
		},
		"a dropped format": func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields[0].Constraints.Format = nil
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			proposed := clone(t, baseDescriptor())
			change(proposed)
			if violations := checkAgainst(baseDescriptor(), proposed); len(violations) != 0 {
				t.Fatalf("unexpected violations: %+v", violations)
			}
		})
	}
}

func TestIncompatibleChangesAreRefusedWithTheirRule(t *testing.T) {
	cases := []struct {
		name   string
		change func(descriptor *registrycompat.Descriptor)
		rules  []string
		path   string
	}{
		{"field number reused for another name", func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields[1].Name = "remark"
		}, []string{registrycompat.RuleFieldOrdinalReused}, "models.Task.fields[2]"},
		{"field type changed", func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields[1].Value.Scalar = "bytes"
		}, []string{registrycompat.RuleFieldTypeChanged}, "models.Task.fields[2]"},
		{"decimal precision changed", func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields[1].Value = registrycompat.Shape{Kind: "decimal", Precision: 10, Scale: 2}
		}, []string{registrycompat.RuleFieldTypeChanged}, "models.Task.fields[2]"},
		{"enum reference changed", func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields[3].Value.Name = "Other"
		}, []string{registrycompat.RuleFieldTypeChanged}, "models.Task.fields[4]"},
		{"singular became a list", func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields[1].Container = registrycompat.Container{Kind: "repeatedLen"}
		}, []string{registrycompat.RuleFieldContainerChanged}, "models.Task.fields[2]"},
		{"list became a map", func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields[2].Container = registrycompat.Container{Kind: "map", Key: "string"}
		}, []string{registrycompat.RuleFieldContainerChanged}, "models.Task.fields[3]"},
		{"optional became required", func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields[1].Container.Nullable = false
		}, []string{registrycompat.RuleFieldNullability}, "models.Task.fields[2]"},
		{"required became optional", func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields[0].Container.Nullable = true
		}, []string{registrycompat.RuleFieldNullability}, "models.Task.fields[1]"},
		{"list became nullable", func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields[2].Container = registrycompat.Container{Kind: "wrapperRepeated"}
		}, []string{registrycompat.RuleFieldNullability}, "models.Task.fields[3]"},
		{"a new required field", func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields = append(taskModel(descriptor).Fields, scalarField(7, "owner", "string"))
		}, []string{registrycompat.RuleRequiredFieldAdded}, "models.Task.fields[7]"},
		{"enum number reused", func(descriptor *registrycompat.Descriptor) {
			descriptor.Enums[0].Variants[1].Name = "finished"
		}, []string{registrycompat.RuleEnumOrdinalReused}, "enums.Status.variants[2]"},
		{"enum variant renumbered", func(descriptor *registrycompat.Descriptor) {
			descriptor.Enums[0].Variants[1].Ordinal = 7
		}, []string{registrycompat.RuleEnumVariantRenumbered}, "enums.Status.variants[2]"},
		{"oneof number reused", func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields[4].Value.Variants[1].Name = "total"
		}, []string{registrycompat.RuleOneofOrdinalReused}, "models.Task.fields[5].oneof[2]"},
		{"oneof variant type changed", func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields[4].Value.Variants[1].Value.Scalar = "u64"
		}, []string{registrycompat.RuleOneofVariantType}, "models.Task.fields[5].oneof[2]"},
		{"node kind removed", func(descriptor *registrycompat.Descriptor) {
			descriptor.Nodes = nil
		}, []string{registrycompat.RuleNodeKindRemoved}, "nodes.item"},
		{"node kind mapped to another model", func(descriptor *registrycompat.Descriptor) {
			descriptor.Models = append(descriptor.Models, registrycompat.Model{Name: "Job", Fields: []registrycompat.Field{scalarField(1, "title", "string")}})
			descriptor.Nodes[0].Model = "Job"
		}, []string{registrycompat.RuleNodeModelChanged}, "nodes.item"},
		{"field moved to another facet", func(descriptor *registrycompat.Descriptor) {
			descriptor.Nodes[0].Facets[0].Fields = []int{1, 2, 3, 6}
			descriptor.Nodes[0].Facets[1].Fields = []int{4, 5}
		}, []string{registrycompat.RuleFieldFacetMoved}, "nodes.item.facets.Availability.fields[6]"},
		{"facet tag changed", func(descriptor *registrycompat.Descriptor) {
			descriptor.Nodes[0].Facets[1].Tag = 9999
		}, []string{registrycompat.RuleFacetTagChanged, registrycompat.RuleFieldFacetMoved, registrycompat.RuleFieldFacetMoved, registrycompat.RuleFieldFacetMoved}, "nodes.item.facets.Availability"},
		{"minimum raised", func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields[0].Constraints.MinLength = number("2")
		}, []string{registrycompat.RuleConstraintTightened}, "models.Task.fields[1]"},
		{"maximum lowered", func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields[0].Constraints.MaxLength = number("100")
		}, []string{registrycompat.RuleConstraintTightened}, "models.Task.fields[1]"},
		{"a bound added", func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields[1].Constraints.MaxLength = number("50")
		}, []string{registrycompat.RuleConstraintTightened}, "models.Task.fields[2]"},
		{"a large integer bound lowered by one", func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields[5].Constraints.MaxValue = number("9223372036854775806")
		}, []string{registrycompat.RuleConstraintTightened}, "models.Task.fields[6]"},
		{"a pattern added", func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields[1].Constraints.Pattern = text("^[a-z]+$")
		}, []string{registrycompat.RuleConstraintTightened}, "models.Task.fields[2]"},
		{"a format changed", func(descriptor *registrycompat.Descriptor) {
			taskModel(descriptor).Fields[0].Constraints.Format = text("email")
		}, []string{registrycompat.RuleConstraintTightened}, "models.Task.fields[1]"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			proposed := clone(t, baseDescriptor())
			testCase.change(proposed)
			violations := checkAgainst(baseDescriptor(), proposed)
			if !slices.Equal(ruleNames(violations), sortedCopy(testCase.rules)) {
				t.Fatalf("rules %v, want %v: %+v", ruleNames(violations), testCase.rules, violations)
			}
			if violations[0].Path != testCase.path && !hasPath(violations, testCase.path) {
				t.Fatalf("no violation at %s: %+v", testCase.path, violations)
			}
		})
	}
}

func sortedCopy(rules []string) []string {
	copied := slices.Clone(rules)
	slices.Sort(copied)
	return copied
}

func hasPath(violations []registrycompat.Violation, path string) bool {
	for _, violation := range violations {
		if violation.Path == path {
			return true
		}
	}
	return false
}

func TestAViolationNamesTheVersionItConflictsWith(t *testing.T) {
	proposed := clone(t, baseDescriptor())
	taskModel(proposed).Fields[1].Name = "remark"
	violations := checkAgainst(baseDescriptor(), proposed)
	if len(violations) != 1 || violations[0].Message != `field number 2 was "note" and is now "remark" (conflicts with version 1.0.0)` {
		t.Fatalf("unexpected violations: %+v", violations)
	}
}

func TestADescriptorWithoutNodesAfterOneWithNodesIsRefused(t *testing.T) {
	violations := checkAgainst(baseDescriptor(), &registrycompat.Descriptor{})
	if !slices.Equal(ruleNames(violations), []string{registrycompat.RuleNodeKindRemoved}) {
		t.Fatalf("unexpected violations: %+v", violations)
	}
}

func TestParseRefusesAWrongShape(t *testing.T) {
	if _, err := registrycompat.Parse(`{"models": "no"}`); err == nil {
		t.Fatal("a descriptor whose models are not a list must not parse")
	}
	empty, err := registrycompat.Parse("")
	if err != nil || len(empty.Nodes) != 0 {
		t.Fatalf("an empty text is a descriptor without nodes: %+v %v", empty, err)
	}
}

func TestAMapKeyChangeIsAContainerChange(t *testing.T) {
	older := baseDescriptor()
	taskModel(older).Fields[2].Container = registrycompat.Container{Kind: "map", Key: "u32"}
	proposed := clone(t, older)
	taskModel(proposed).Fields[2].Container.Key = "string"
	if rules := ruleNames(checkAgainst(older, proposed)); !slices.Equal(rules, []string{registrycompat.RuleFieldContainerChanged}) {
		t.Fatalf("rules %v", rules)
	}
}

func TestTitleSearchableAndTimeRangeMayChange(t *testing.T) {
	const template = `{"models":[{"name":"Event","fields":[
		{"ordinal":1,"name":"title","container":{"kind":"singular","nullable":false},"value":{"kind":"scalar","scalar":"string"},"required":true,"constraints":{}},
		{"ordinal":2,"name":"start","container":{"kind":"singular","nullable":false},"value":{"kind":"scalar","scalar":"timestamp"},"required":true,"constraints":{}}]}],
		"nodes":[{"kind":"item","model":"Event","facets":[{"name":"default","tag":1,"fields":[1,2]}],%s}]}`
	older, err := registrycompat.Parse(fmt.Sprintf(template, `"searchable":[1],"title":1,"timeRange":{"start":2,"end":2}`))
	if err != nil {
		t.Fatal(err)
	}
	proposed, err := registrycompat.Parse(fmt.Sprintf(template, `"searchable":[],"title":2,"timeRange":null`))
	if err != nil {
		t.Fatal(err)
	}
	if violations := checkAgainst(older, proposed); len(violations) != 0 {
		t.Fatalf("unexpected violations: %+v", violations)
	}
}
