package registrycompat

import "fmt"

const (
	RuleEnumOrdinalReused     = "enum_ordinal_reused"
	RuleEnumVariantRenumbered = "enum_variant_renumbered"
)

func (c *comparison) checkEnums() {
	for _, olderEnum := range c.older.Enums {
		newerEnum, found := c.newer.enum(olderEnum.Name)
		if found {
			c.checkEnum(olderEnum, newerEnum)
		}
	}
}

func (c *comparison) checkEnum(olderEnum, newerEnum Enum) {
	for _, olderVariant := range olderEnum.Variants {
		c.checkEnumVariant(olderEnum.Name, olderVariant, newerEnum)
	}
}

func (c *comparison) checkEnumVariant(enumName string, olderVariant EnumVariant, newerEnum Enum) {
	path := fmt.Sprintf("enums.%s.variants[%d]", enumName, olderVariant.Ordinal)
	for _, newerVariant := range newerEnum.Variants {
		if newerVariant.Ordinal == olderVariant.Ordinal && newerVariant.Name != olderVariant.Name {
			c.report(RuleEnumOrdinalReused, path, "variant number %d of %s was %q and is now %q", olderVariant.Ordinal, enumName, olderVariant.Name, newerVariant.Name)
		}
		if newerVariant.Name == olderVariant.Name && newerVariant.Ordinal != olderVariant.Ordinal {
			c.report(RuleEnumVariantRenumbered, path, "variant %q of %s moved from number %d to %d", olderVariant.Name, enumName, olderVariant.Ordinal, newerVariant.Ordinal)
		}
	}
}
