package applogo

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strconv"
	"strings"
)

const (
	svgNamespace   = "http://www.w3.org/2000/svg"
	xlinkNamespace = "http://www.w3.org/1999/xlink"

	maxSVGElements = 2000
	maxSVGDepth    = 32
)

var allowedElements = setOf(
	"svg", "g", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon", "defs",
	"linearGradient", "radialGradient", "stop", "clipPath", "mask", "title", "desc", "text", "tspan",
	"symbol", "use",
)

var textElements = setOf("title", "desc", "text", "tspan")

var allowedAttributes = setOf(
	"id", "class", "viewBox", "width", "height", "x", "y", "x1", "y1", "x2", "y2", "cx", "cy", "r", "rx", "ry",
	"d", "points", "transform", "fill", "fill-opacity", "fill-rule", "stroke", "stroke-width", "stroke-opacity",
	"stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-dasharray", "stroke-dashoffset", "opacity",
	"offset", "stop-color", "stop-opacity", "gradientUnits", "gradientTransform", "spreadMethod", "fx", "fy",
	"clip-path", "clip-rule", "clipPathUnits", "mask", "maskUnits", "maskContentUnits", "display", "visibility",
	"font-family", "font-size", "font-weight", "font-style", "text-anchor", "dominant-baseline", "dx", "dy",
	"preserveAspectRatio", "style", "href", "version",
)

// referenceAttributes may hold url(#id); anything else inside url() is refused.
var referenceAttributes = setOf("fill", "stroke", "clip-path", "mask")

var allowedStyleProperties = setOf(
	"fill", "fill-opacity", "fill-rule", "stroke", "stroke-width", "stroke-opacity", "stroke-linecap",
	"stroke-linejoin", "stroke-miterlimit", "stroke-dasharray", "stroke-dashoffset", "opacity", "stop-color",
	"stop-opacity", "clip-path", "clip-rule", "mask", "display", "visibility", "font-family", "font-size",
	"font-weight", "font-style", "text-anchor", "dominant-baseline",
)

func setOf(names ...string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set
}

type sanitizer struct {
	output   strings.Builder
	open     []string
	elements int
	sawRoot  bool
}

func validateSVG(body []byte) (*Logo, error) {
	if len(body) > MaxSVGBytes {
		return nil, invalid("an SVG logo is at most %d KB", MaxSVGBytes>>10)
	}
	cleaned, err := sanitizeSVG(body)
	if err != nil {
		return nil, err
	}
	return newLogo(ContentTypeSVG, cleaned, ""), nil
}

func sanitizeSVG(body []byte) ([]byte, error) {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	decoder.Strict = true
	state := &sanitizer{}
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, invalid("the file is neither a PNG nor a well-formed SVG")
		}
		if err := state.accept(token); err != nil {
			return nil, err
		}
	}
	if !state.sawRoot || len(state.open) != 0 {
		return nil, invalid("the file is neither a PNG nor a well-formed SVG")
	}
	return []byte(state.output.String()), nil
}

func (state *sanitizer) accept(token xml.Token) error {
	switch typed := token.(type) {
	case xml.StartElement:
		return state.start(typed)
	case xml.EndElement:
		state.end()
	case xml.CharData:
		return state.text(typed)
	case xml.Directive:
		return invalid("an SVG logo cannot contain a DOCTYPE or entity declarations")
	}
	return nil
}

func (state *sanitizer) start(element xml.StartElement) error {
	if err := state.checkElement(element); err != nil {
		return err
	}
	state.sawRoot = true
	state.elements++
	state.open = append(state.open, element.Name.Local)
	state.output.WriteString("<" + element.Name.Local)
	if len(state.open) == 1 {
		state.output.WriteString(` xmlns="` + svgNamespace + `" xmlns:xlink="` + xlinkNamespace + `"`)
	}
	attributes, err := cleanAttributes(element)
	if err != nil {
		return err
	}
	state.output.WriteString(attributes + ">")
	return nil
}

func (state *sanitizer) checkElement(element xml.StartElement) error {
	if state.sawRoot && len(state.open) == 0 {
		return invalid("an SVG logo has one root element")
	}
	if !state.sawRoot && element.Name.Local != "svg" {
		return invalid("the root element must be svg")
	}
	if element.Name.Space != svgNamespace {
		return invalid("<%s> is not in the SVG namespace", element.Name.Local)
	}
	if !allowedElements[element.Name.Local] {
		return invalid("<%s> is not allowed in an SVG logo", element.Name.Local)
	}
	if state.elements >= maxSVGElements || len(state.open) >= maxSVGDepth {
		return invalid("the SVG is too complex")
	}
	return nil
}

func (state *sanitizer) end() {
	name := state.open[len(state.open)-1]
	state.open = state.open[:len(state.open)-1]
	state.output.WriteString("</" + name + ">")
}

func (state *sanitizer) text(data xml.CharData) error {
	if len(state.open) == 0 || textElements[state.open[len(state.open)-1]] {
		return state.writeText(data)
	}
	if strings.TrimSpace(string(data)) != "" {
		return invalid("text is only allowed inside text, title and desc")
	}
	return nil
}

func (state *sanitizer) writeText(data xml.CharData) error {
	if len(state.open) == 0 {
		return nil
	}
	return xml.EscapeText(&state.output, data)
}

func cleanAttributes(element xml.StartElement) (string, error) {
	var written strings.Builder
	for _, attribute := range element.Attr {
		name, keep := attributeName(attribute.Name)
		if !keep {
			continue
		}
		value, err := cleanValue(name, attribute.Value)
		if err != nil {
			return "", err
		}
		if value == "" && name == "style" {
			continue
		}
		written.WriteString(" " + name + `="` + escapeAttribute(value) + `"`)
	}
	if element.Name.Local == "svg" {
		return checkRootSize(element, written.String())
	}
	return written.String(), nil
}

// attributeName maps an attribute to its output name; attributes outside the
// allowlist, namespace declarations and event handlers are dropped.
func attributeName(name xml.Name) (string, bool) {
	if name.Space == xlinkNamespace && name.Local == "href" {
		return "xlink:href", true
	}
	if name.Space != "" || !allowedAttributes[name.Local] {
		return "", false
	}
	return name.Local, true
}

func cleanValue(name string, value string) (string, error) {
	if name == "style" {
		return cleanStyle(value), nil
	}
	if name == "href" || name == "xlink:href" {
		return value, requireLocalReference(value)
	}
	return value, checkURLReferences(name, value)
}

func requireLocalReference(value string) error {
	if !strings.HasPrefix(strings.TrimSpace(value), "#") {
		return invalid("an SVG logo cannot reference anything outside the file")
	}
	return nil
}

// checkURLReferences refuses url() values other than a reference to an id in the
// file, and script-like values in any attribute.
func checkURLReferences(name string, value string) error {
	lowered := strings.ToLower(value)
	if strings.Contains(lowered, "javascript:") || strings.Contains(lowered, "data:") {
		return invalid("the %s attribute holds a script or data URL", name)
	}
	if !strings.Contains(lowered, "url(") {
		return nil
	}
	if !referenceAttributes[name] || !onlyLocalURLs(lowered) {
		return invalid("the %s attribute cannot reference anything outside the file", name)
	}
	return nil
}

// onlyLocalURLs reports whether every url( in the text is followed by #.
func onlyLocalURLs(text string) bool {
	for {
		index := strings.Index(text, "url(")
		if index < 0 {
			return true
		}
		rest := strings.TrimLeft(text[index+len("url("):], " \t'\"")
		if !strings.HasPrefix(rest, "#") {
			return false
		}
		text = rest
	}
}

// cleanStyle keeps the declarations of an allowed property whose value holds no
// external reference.
func cleanStyle(value string) string {
	kept := []string{}
	for _, declaration := range strings.Split(value, ";") {
		property, setting, found := strings.Cut(declaration, ":")
		property = strings.ToLower(strings.TrimSpace(property))
		if !found || !allowedStyleProperties[property] || !safeStyleValue(setting) {
			continue
		}
		kept = append(kept, property+":"+strings.TrimSpace(setting))
	}
	return strings.Join(kept, ";")
}

func safeStyleValue(setting string) bool {
	lowered := strings.ToLower(setting)
	for _, forbidden := range []string{"@", "\\", "<", "expression", "javascript:", "data:", "behavior"} {
		if strings.Contains(lowered, forbidden) {
			return false
		}
	}
	return !strings.Contains(lowered, "url(") || onlyLocalURLs(lowered)
}

func escapeAttribute(value string) string {
	var escaped bytes.Buffer
	_ = xml.EscapeText(&escaped, []byte(value))
	return escaped.String()
}

// checkRootSize requires the root to declare its size, so a logo has dimensions
// to limit: a viewBox, or a width and a height.
func checkRootSize(element xml.StartElement, written string) (string, error) {
	width, height, found := declaredSize(element)
	if !found {
		return "", invalid("the root svg needs a viewBox or a width and a height")
	}
	if width <= 0 || height <= 0 || width > maxSVGDimens || height > maxSVGDimens {
		return "", invalid("an SVG logo is at most %d units on each side", maxSVGDimens)
	}
	if width > height*maxAspectRatio || height > width*maxAspectRatio {
		return "", invalid("a logo is at most %d times wider than tall", maxAspectRatio)
	}
	return written, nil
}

func declaredSize(element xml.StartElement) (float64, float64, bool) {
	attributes := map[string]string{}
	for _, attribute := range element.Attr {
		attributes[attribute.Name.Local] = attribute.Value
	}
	if box := strings.Fields(strings.ReplaceAll(attributes["viewBox"], ",", " ")); len(box) == 4 {
		return parseUnits(box[2]), parseUnits(box[3]), true
	}
	if attributes["width"] != "" && attributes["height"] != "" {
		return parseUnits(attributes["width"]), parseUnits(attributes["height"]), true
	}
	return 0, 0, false
}

// parseUnits reads a number with an optional px suffix; anything else is 0.
func parseUnits(text string) float64 {
	number, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(text), "px"), 64)
	if err != nil {
		return 0
	}
	return number
}
