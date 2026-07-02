// Package linkpreview proxies Open Graph metadata for URLs shared in chat.
//
// Clients can't scrape arbitrary sites directly from a browser (CORS), so the
// server fetches the page, extracts a few <meta> tags, and returns them as JSON.
// The endpoint is mounted behind client auth and refuses private/loopback hosts
// to limit SSRF.
package linkpreview

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

const (
	fetchTimeout = 6 * time.Second
	maxBodyBytes = 1 << 20 // 1 MiB of HTML is plenty for <head> metadata.
)

type Handler struct {
	client *http.Client
}

func NewHandler() *Handler {
	return &Handler{client: &http.Client{Timeout: fetchTimeout}}
}

func (h *Handler) Register(r chi.Router) {
	r.Get("/api/v1/link-preview", h.preview)
}

type preview struct {
	URL         string `json:"url"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Image       string `json:"image,omitempty"`
	SiteName    string `json:"siteName,omitempty"`
}

func (h *Handler) preview(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		http.Error(w, "invalid url", http.StatusBadRequest)
		return
	}
	if isBlockedHost(parsed.Hostname()) {
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}

	html, err := h.fetch(r.Context(), target)
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}

	result := extract(html, parsed)
	result.URL = target

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func (h *Handler) fetch(ctx context.Context, target string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "NeoWorksChat/1.0 (+link-preview)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	res, err := h.client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if !strings.Contains(res.Header.Get("Content-Type"), "text/html") {
		return "", errNotHTML
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBodyBytes))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

var errNotHTML = &previewError{"not html"}

type previewError struct{ msg string }

func (e *previewError) Error() string { return e.msg }

var (
	metaRe  = regexp.MustCompile(`(?is)<meta\s+[^>]*>`)
	titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	attrRe  = regexp.MustCompile(`(?is)(property|name|content)\s*=\s*("([^"]*)"|'([^']*)')`)
)

// extract pulls og:* / twitter:* / description metadata out of the page head.
func extract(html string, base *url.URL) preview {
	var result preview
	metas := map[string]string{}

	for _, tag := range metaRe.FindAllString(html, -1) {
		var key, content string
		for _, m := range attrRe.FindAllStringSubmatch(tag, -1) {
			value := m[3]
			if value == "" {
				value = m[4]
			}
			switch strings.ToLower(m[1]) {
			case "property", "name":
				key = strings.ToLower(value)
			case "content":
				content = value
			}
		}
		if key != "" && content != "" {
			if _, exists := metas[key]; !exists {
				metas[key] = htmlUnescape(content)
			}
		}
	}

	result.Title = firstOf(metas, "og:title", "twitter:title")
	if result.Title == "" {
		if m := titleRe.FindStringSubmatch(html); m != nil {
			result.Title = htmlUnescape(strings.TrimSpace(m[1]))
		}
	}
	result.Description = firstOf(metas, "og:description", "twitter:description", "description")
	result.SiteName = firstOf(metas, "og:site_name")

	if image := firstOf(metas, "og:image", "twitter:image"); image != "" {
		if ref, err := url.Parse(image); err == nil {
			result.Image = base.ResolveReference(ref).String()
		}
	}
	return result
}

func firstOf(metas map[string]string, keys ...string) string {
	for _, key := range keys {
		if v := metas[key]; v != "" {
			return v
		}
	}
	return ""
}

func htmlUnescape(s string) string {
	replacer := strings.NewReplacer(
		"&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", "\"", "&#39;", "'", "&#x27;", "'",
	)
	return replacer.Replace(s)
}

// isBlockedHost rejects loopback, link-local and private ranges to limit SSRF.
func isBlockedHost(host string) bool {
	if host == "" || strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false // hostnames resolve at dial time; only block literal private IPs.
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}
