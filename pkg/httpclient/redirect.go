package httpclient

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var (
	// <meta http-equiv="refresh" ...> - attribute order may vary, case-insensitive
	metaRefreshTagRe = regexp.MustCompile(`(?is)<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*>`)
	// url= inside a Refresh header value or meta content value
	refreshURLRe = regexp.MustCompile(`(?i)url\s*=\s*["']?([^"'\s>]+)`)
)

// EffectiveFinalURL returns the effective destination after all redirect signals:
// HTTP 3xx (already resolved by http.Client), the Refresh response header, and
// <meta http-equiv="refresh"> tags in the body. Callers should use this instead
// of resp.Request.URL directly so that non-3xx redirect mechanisms are covered.
func EffectiveFinalURL(resp *http.Response, body []byte) *url.URL {
	base := resp.Request.URL

	if target := parseRefreshHeader(resp.Header.Get("Refresh"), base); target != nil {
		return target
	}
	if target := parseMetaRefresh(body, base); target != nil {
		return target
	}
	return base
}

func parseRefreshHeader(header string, base *url.URL) *url.URL {
	if header == "" {
		return nil
	}
	m := refreshURLRe.FindStringSubmatch(header)
	if m == nil {
		return nil
	}
	t, err := url.Parse(m[1])
	if err != nil {
		return nil
	}
	if base != nil {
		return base.ResolveReference(t)
	}
	return t
}

func parseMetaRefresh(body []byte, base *url.URL) *url.URL {
	tag := metaRefreshTagRe.Find(body)
	if tag == nil {
		return nil
	}
	m := refreshURLRe.FindSubmatch(tag)
	if m == nil {
		return nil
	}
	t, err := url.Parse(string(m[1]))
	if err != nil {
		return nil
	}
	if base != nil {
		return base.ResolveReference(t)
	}
	return t
}

func normalizedPath(path string) string {
	trimmed := strings.TrimRight(path, "/")
	if trimmed == "" {
		return "/"
	}
	return trimmed
}

// Redirected reports whether the final URL differs from the originally
// requested URL after http.Client redirect handling.
func Redirected(requestedURL, finalURL *url.URL) bool {
	if requestedURL == nil || finalURL == nil {
		return false
	}
	return finalURL.Scheme != requestedURL.Scheme ||
		finalURL.Host != requestedURL.Host ||
		normalizedPath(finalURL.Path) != normalizedPath(requestedURL.Path) ||
		finalURL.RawQuery != requestedURL.RawQuery
}

// RedirectLooksSafe classifies redirects to clearly benign login/auth pages.
// It is intentionally conservative: only obvious safe landing pages are
// treated as non-threatening.
func RedirectLooksSafe(requestedURL, finalURL *url.URL, contentType string, body []byte) bool {

	if !Redirected(requestedURL, finalURL) {
		return false
	}

	safePaths := map[string]struct{}{
		"/login":          {},
		"/signin":         {},
		"/auth":           {},
		"/auth/login":     {},
		"/account/login":  {},
		"/user/login":     {},
		"/users/sign_in":  {},
		"/sso/login":      {},
		"/oauth2/login":   {},
		"/oauth2/sign_in": {},
		"/session":        {},
	}

	if _, ok := safePaths[normalizedPath(finalURL.Path)]; ok {
		return true
	}

	bodyLower := strings.ToLower(string(body))
	contentTypeLower := strings.ToLower(contentType)
	if strings.Contains(contentTypeLower, "html") || strings.Contains(contentTypeLower, "xhtml") || strings.Contains(contentTypeLower, "xml") {
		authIndicators := []string{
			"login", "sign in", "signin", "authenticate", "authentication",
			"password", "username", "session expired", "mfa", "two-factor", "2fa",
		}
		matches := 0
		for _, indicator := range authIndicators {
			if strings.Contains(bodyLower, indicator) {
				matches++
			}
		}
		if matches >= 2 {
			return true
		}
	}

	return false
}
