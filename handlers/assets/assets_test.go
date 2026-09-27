package assets

import (
	"net/http/httptest"
	"testing"
)

func served(contentType string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	writeBytes(recorder, contentType, []byte("payload"))
	return recorder
}

func TestWriteBytesRendersSafeImagesInline(t *testing.T) {
	for _, contentType := range []string{"image/png", "image/jpeg", "IMAGE/WEBP", "image/avif; q=1"} {
		recorder := served(contentType)
		if disposition := recorder.Header().Get("Content-Disposition"); disposition != "" {
			t.Errorf("%s: Content-Disposition = %q, want inline", contentType, disposition)
		}
		if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing nosniff", contentType)
		}
	}
}

// Anything a browser could execute is downloaded, never rendered on the asset
// origin — SVG included, since it can carry script.
func TestWriteBytesDownloadsEverythingElse(t *testing.T) {
	for _, contentType := range []string{"text/html", "image/svg+xml", "application/pdf", "application/octet-stream", "", "not a type"} {
		recorder := served(contentType)
		if disposition := recorder.Header().Get("Content-Disposition"); disposition != "attachment" {
			t.Errorf("%q: Content-Disposition = %q, want attachment", contentType, disposition)
		}
		if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%q: missing nosniff", contentType)
		}
		if recorder.Header().Get("Content-Security-Policy") != "default-src 'none'; sandbox" {
			t.Errorf("%q: missing sandbox CSP", contentType)
		}
	}
}
