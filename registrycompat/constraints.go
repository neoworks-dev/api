package registrycompat

import (
	"encoding/json"
	"math/big"
)

const RuleConstraintTightened = "constraint_tightened"

// checkConstraints requires constraints to stay as loose as they were, so content
// stored under an earlier version stays valid.
func (c *comparison) checkConstraints(path string, olderField, newerField Field) {
	older, newer := olderField.Constraints, newerField.Constraints
	bounds := []numericBound{
		{name: "minValue", lower: true, older: older.MinValue, newer: newer.MinValue},
		{name: "maxValue", lower: false, older: older.MaxValue, newer: newer.MaxValue},
		{name: "minLength", lower: true, older: older.MinLength, newer: newer.MinLength},
		{name: "maxLength", lower: false, older: older.MaxLength, newer: newer.MaxLength},
	}
	for _, bound := range bounds {
		if bound.tightened() {
			c.report(RuleConstraintTightened, path, "%q on %q tightened from %s to %s", bound.name, newerField.Name, showNumber(bound.older), showNumber(bound.newer))
		}
	}
	c.checkText(path, newerField.Name, "pattern", older.Pattern, newer.Pattern)
	c.checkText(path, newerField.Name, "format", older.Format, newer.Format)
}

// checkText accepts removing a pattern or format and keeping it. A different
// pattern cannot be proven to accept everything the old one did, so it counts
// as tightening.
func (c *comparison) checkText(path, fieldName, constraint string, older, newer *string) {
	if newer == nil || (older != nil && *older == *newer) {
		return
	}
	c.report(RuleConstraintTightened, path, "%q on %q is now %q; content stored earlier may not match it", constraint, fieldName, *newer)
}

// numericBound is a bound that must not move inward: a lower bound must not
// rise and an upper bound must not fall.
type numericBound struct {
	name  string
	lower bool
	older *json.Number
	newer *json.Number
}

func (bound numericBound) tightened() bool {
	if bound.newer == nil {
		return false
	}
	if bound.older == nil {
		return true
	}
	olderValue, olderOK := parseNumber(*bound.older)
	newerValue, newerOK := parseNumber(*bound.newer)
	if !olderOK || !newerOK {
		return *bound.older != *bound.newer
	}
	if bound.lower {
		return newerValue.Cmp(olderValue) > 0
	}
	return newerValue.Cmp(olderValue) < 0
}

func parseNumber(number json.Number) (*big.Rat, bool) {
	return new(big.Rat).SetString(number.String())
}

func showNumber(number *json.Number) string {
	if number == nil {
		return "none"
	}
	return number.String()
}
