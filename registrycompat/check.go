package registrycompat

import "fmt"

// Violation is one way a proposed version breaks an earlier one. Path points
// into the descriptor, e.g. models.Song.fields[6].
type Violation struct {
	Rule    string `json:"rule"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

// Version is a published version and its descriptor.
type Version struct {
	Version    string
	Descriptor *Descriptor
}

// Check compares the proposed descriptor with every published version and
// returns all violations, none when the proposal is compatible with all of them.
// Versions without a descriptor define no nodes and are skipped.
func Check(published []Version, proposed *Descriptor) []Violation {
	violations := []Violation{}
	for _, version := range published {
		if version.Descriptor == nil {
			continue
		}
		comparison := comparison{version: version.Version, older: version.Descriptor, newer: proposed}
		violations = append(violations, comparison.violations()...)
	}
	return violations
}

// comparison collects the violations of one proposed descriptor against one
// published version.
type comparison struct {
	version string
	older   *Descriptor
	newer   *Descriptor
	found   []Violation
}

func (c *comparison) violations() []Violation {
	c.checkModels()
	c.checkEnums()
	c.checkNodes()
	return c.found
}

func (c *comparison) report(rule, path, format string, arguments ...any) {
	message := fmt.Sprintf(format, arguments...) + fmt.Sprintf(" (conflicts with version %s)", c.version)
	c.found = append(c.found, Violation{Rule: rule, Path: path, Message: message})
}
