package registrycompat

import (
	"fmt"
	"slices"
)

const (
	RuleNodeKindRemoved  = "node_kind_removed"
	RuleNodeModelChanged = "node_model_changed"
	RuleFacetTagChanged  = "facet_tag_changed"
	RuleFieldFacetMoved  = "field_facet_changed"
)

func (c *comparison) checkNodes() {
	for _, olderNode := range c.older.Nodes {
		path := "nodes." + olderNode.Kind
		newerNode, found := c.newer.node(olderNode.Kind)
		if !found {
			c.report(RuleNodeKindRemoved, path, "%s nodes stored %s and the schema no longer defines them", olderNode.Kind, olderNode.Model)
			continue
		}
		c.checkNode(path, olderNode, newerNode)
	}
}

func (c *comparison) checkNode(path string, olderNode, newerNode Node) {
	if olderNode.Model != newerNode.Model {
		c.report(RuleNodeModelChanged, path, "%s nodes are stored as %s and would now be %s", olderNode.Kind, olderNode.Model, newerNode.Model)
		return
	}
	for _, olderFacet := range olderNode.Facets {
		c.checkFacet(path, olderFacet, newerNode)
	}
}

func (c *comparison) checkFacet(nodePath string, olderFacet Facet, newerNode Node) {
	facetPath := fmt.Sprintf("%s.facets.%s", nodePath, olderFacet.Name)
	for _, newerFacet := range newerNode.Facets {
		if newerFacet.Name == olderFacet.Name && newerFacet.Tag != olderFacet.Tag {
			c.report(RuleFacetTagChanged, facetPath, "facet %q changed its tag from %d to %d", olderFacet.Name, olderFacet.Tag, newerFacet.Tag)
		}
	}
	for _, ordinal := range olderFacet.Fields {
		c.checkFacetField(facetPath, olderFacet, ordinal, newerNode)
	}
}

// checkFacetField requires a field to stay in the facet it was written in: the
// facet decides which grants can read it.
func (c *comparison) checkFacetField(facetPath string, olderFacet Facet, ordinal int, newerNode Node) {
	for _, newerFacet := range newerNode.Facets {
		if slices.Contains(newerFacet.Fields, ordinal) && newerFacet.Tag != olderFacet.Tag {
			c.report(RuleFieldFacetMoved, fmt.Sprintf("%s.fields[%d]", facetPath, ordinal),
				"field %d moved from facet %q to facet %q", ordinal, olderFacet.Name, newerFacet.Name)
		}
	}
}
