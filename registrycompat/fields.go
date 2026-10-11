package registrycompat

import "fmt"

const (
	RuleFieldOrdinalReused    = "field_ordinal_reused"
	RuleFieldTypeChanged      = "field_type_changed"
	RuleFieldContainerChanged = "field_container_changed"
	RuleFieldNullability      = "field_nullability_changed"
	RuleRequiredFieldAdded    = "required_field_added"
	RuleOneofOrdinalReused    = "oneof_ordinal_reused"
	RuleOneofVariantType      = "oneof_variant_type_changed"
)

func (c *comparison) checkModels() {
	for _, olderModel := range c.older.Models {
		newerModel, found := c.newer.model(olderModel.Name)
		if found {
			c.checkModel(olderModel, newerModel)
		}
	}
}

func (c *comparison) checkModel(olderModel, newerModel Model) {
	for _, newerField := range newerModel.Fields {
		olderField, existed := olderModel.field(newerField.Ordinal)
		path := fieldPath(newerModel.Name, newerField.Ordinal)
		if existed {
			c.checkField(path, olderField, newerField)
			continue
		}
		if newerField.Required {
			c.report(RuleRequiredFieldAdded, path, "new field %q is required; new fields of an existing model must be optional", newerField.Name)
		}
	}
}

func fieldPath(model string, ordinal int) string {
	return fmt.Sprintf("models.%s.fields[%d]", model, ordinal)
}

func (c *comparison) checkField(path string, olderField, newerField Field) {
	if olderField.Name != newerField.Name {
		c.report(RuleFieldOrdinalReused, path, "field number %d was %q and is now %q", olderField.Ordinal, olderField.Name, newerField.Name)
		return
	}
	c.checkContainer(path, olderField, newerField)
	if !sameShape(olderField.Value, newerField.Value) {
		c.report(RuleFieldTypeChanged, path, "type of %q changed from %s to %s", newerField.Name, describeShape(olderField.Value), describeShape(newerField.Value))
	} else {
		c.checkOneof(path, olderField.Value, newerField.Value)
	}
	c.checkConstraints(path, olderField, newerField)
}

func (c *comparison) checkContainer(path string, olderField, newerField Field) {
	olderContainer, newerContainer := olderField.Container, newerField.Container
	if olderContainer.category() != newerContainer.category() || olderContainer.Key != newerContainer.Key {
		c.report(RuleFieldContainerChanged, path, "%q changed from %s to %s", newerField.Name, describeContainer(olderContainer), describeContainer(newerContainer))
		return
	}
	if olderContainer.nullable() != newerContainer.nullable() {
		c.report(RuleFieldNullability, path, "%q changed from %s to %s", newerField.Name, describeNullability(olderContainer), describeNullability(newerContainer))
	}
}

func describeContainer(container Container) string {
	switch container.category() {
	case "list":
		return "a list"
	case "map":
		return "a map keyed by " + container.Key
	default:
		return "a single value"
	}
}

func describeNullability(container Container) string {
	if container.nullable() {
		return "optional"
	}
	return "required"
}

func describeShape(shape Shape) string {
	switch shape.Kind {
	case "scalar":
		return shape.Scalar
	case "enum", "message":
		return shape.Kind + " " + shape.Name
	case "decimal":
		return fmt.Sprintf("decimal(%d, %d)", shape.Precision, shape.Scale)
	default:
		return shape.Kind
	}
}

// sameShape compares the type of two values. Oneof variants are compared by
// checkOneof, because a oneof may gain variants.
func sameShape(older, newer Shape) bool {
	if older.Kind != newer.Kind {
		return false
	}
	switch older.Kind {
	case "scalar":
		return older.Scalar == newer.Scalar
	case "enum", "message":
		return older.Name == newer.Name
	case "decimal":
		return older.Precision == newer.Precision && older.Scale == newer.Scale
	default:
		return true
	}
}

func (c *comparison) checkOneof(path string, older, newer Shape) {
	if older.Kind != "oneof" {
		return
	}
	for _, olderVariant := range older.Variants {
		newerVariant, found := variantByOrdinal(newer.Variants, olderVariant.Ordinal)
		if found {
			c.checkVariant(fmt.Sprintf("%s.oneof[%d]", path, olderVariant.Ordinal), olderVariant, newerVariant)
		}
	}
}

func variantByOrdinal(variants []OneofVariant, ordinal int) (OneofVariant, bool) {
	for _, variant := range variants {
		if variant.Ordinal == ordinal {
			return variant, true
		}
	}
	return OneofVariant{}, false
}

func (c *comparison) checkVariant(path string, older, newer OneofVariant) {
	if older.Name != newer.Name {
		c.report(RuleOneofOrdinalReused, path, "oneof variant number %d was %q and is now %q", older.Ordinal, older.Name, newer.Name)
		return
	}
	if !sameShape(older.Value, newer.Value) {
		c.report(RuleOneofVariantType, path, "type of oneof variant %q changed from %s to %s", newer.Name, describeShape(older.Value), describeShape(newer.Value))
		return
	}
	c.checkOneof(path, older.Value, newer.Value)
}
