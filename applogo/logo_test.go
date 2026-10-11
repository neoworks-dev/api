package applogo_test

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"

	"github.com/neoworks/auth/applogo"
)

func pngBytes(t *testing.T, width int, height int, paint func(x int, y int) color.Color) []byte {
	t.Helper()
	picture := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			picture.Set(x, y, paint(x, y))
		}
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, picture); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return encoded.Bytes()
}

func halves(x int, y int) color.Color {
	if x < 32 {
		return color.Black
	}
	return color.White
}

func TestPNGLimits(t *testing.T) {
	logo, err := applogo.Validate(pngBytes(t, 128, 128, halves))
	if err != nil {
		t.Fatalf("valid png: %v", err)
	}
	if logo.ContentType != applogo.ContentTypePNG || logo.AHash == "" || logo.SHA256 == "" {
		t.Fatalf("logo: %+v", logo)
	}
	for name, body := range map[string][]byte{
		"too small":  pngBytes(t, 32, 32, halves),
		"too large":  pngBytes(t, 2000, 2000, halves),
		"too wide":   pngBytes(t, 640, 64, halves),
		"empty":      {},
		"not a file": []byte("hello"),
	} {
		if _, err := applogo.Validate(body); !errors.Is(err, applogo.ErrInvalid) {
			t.Errorf("%s: got %v want ErrInvalid", name, err)
		}
	}
}

func TestPNGAreLookalikesWhenTheirPicturesAreAlmostTheSame(t *testing.T) {
	original, _ := applogo.Validate(pngBytes(t, 128, 128, halves))
	slightlyChanged, _ := applogo.Validate(pngBytes(t, 256, 256, func(x int, y int) color.Color {
		if x < 64 || (x == 66 && y < 4) {
			return color.Gray{Y: 10}
		}
		return color.White
	}))
	different, _ := applogo.Validate(pngBytes(t, 128, 128, func(x int, y int) color.Color {
		if y < 64 {
			return color.Black
		}
		return color.White
	}))
	if !applogo.Resembles(original.SHA256, original.AHash, slightlyChanged.SHA256, slightlyChanged.AHash) {
		t.Error("a rescaled copy must resemble the original")
	}
	if applogo.Resembles(original.SHA256, original.AHash, different.SHA256, different.AHash) {
		t.Error("a different picture must not resemble the original")
	}
}

const cleanSVG = `<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 100 100" onload="alert(1)">
  <!-- comment -->
  <defs><linearGradient id="g"><stop offset="0" stop-color="#fff"/></linearGradient></defs>
  <circle cx="50" cy="50" r="40" fill="url(#g)" style="stroke:red;background:url(http://evil.example/x)" onclick="alert(1)"/>
  <use xlink:href="#g"/>
  <title>Logo &amp; more</title>
</svg>`

func TestSVGIsRebuiltFromAllowedParts(t *testing.T) {
	logo, err := applogo.Validate([]byte(cleanSVG))
	if err != nil {
		t.Fatalf("valid svg: %v", err)
	}
	output := string(logo.Data)
	for _, forbidden := range []string{"onload", "onclick", "comment", "evil.example", "background"} {
		if strings.Contains(output, forbidden) {
			t.Errorf("%q survived sanitizing: %s", forbidden, output)
		}
	}
	for _, kept := range []string{`fill="url(#g)"`, `style="stroke:red"`, `xlink:href="#g"`, "Logo &amp; more"} {
		if !strings.Contains(output, kept) {
			t.Errorf("%q was lost: %s", kept, output)
		}
	}
	if logo.ContentType != applogo.ContentTypeSVG || logo.AHash != "" {
		t.Errorf("logo: %+v", logo)
	}
}

func TestSVGRefusesScriptAndExternalReferences(t *testing.T) {
	wrap := func(inner string) []byte {
		return []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">` + inner + `</svg>`)
	}
	cases := map[string][]byte{
		"script":          wrap(`<script>alert(1)</script>`),
		"foreignObject":   wrap(`<foreignObject><div/></foreignObject>`),
		"image":           wrap(`<image href="http://evil.example/a.png"/>`),
		"external use":    wrap(`<use href="http://evil.example/a.svg#x"/>`),
		"external fill":   wrap(`<rect fill="url(http://evil.example/a.svg#x)"/>`),
		"javascript href": wrap(`<use href="javascript:alert(1)"/>`),
		"style element":   wrap(`<style>@import url(http://evil.example)</style>`),
		"doctype":         []byte(`<!DOCTYPE svg [<!ENTITY x "y">]><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/>`),
		"stray text":      wrap(`<g>hello</g>`),
		"wrong namespace": []byte(`<svg viewBox="0 0 10 10"/>`),
		"no size":         []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`),
		"huge":            []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 90000 90000"/>`),
		"not svg":         []byte(`<html xmlns="http://www.w3.org/2000/svg"/>`),
		"two roots":       []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/>`),
		"unclosed":        []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1">`),
		"too many bytes":  append([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><title>`), bytes.Repeat([]byte("a"), applogo.MaxSVGBytes)...),
	}
	for name, body := range cases {
		if _, err := applogo.Validate(body); !errors.Is(err, applogo.ErrInvalid) {
			t.Errorf("%s: got %v want ErrInvalid", name, err)
		}
	}
}
