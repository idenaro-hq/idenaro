package checks

import (
	"net/url"
	"strings"
)

const moduleName = "oidc-pro"

func extractHost(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Host
}

func joinKeys(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			keys = append(keys, k)
		}
	}
	return strings.Join(keys, ", ")
}

func isIPRedirectURI(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return false
	}
	parts := strings.Split(host, ".")
	if len(parts) == 4 {
		for _, p := range parts {
			for _, ch := range p {
				if ch < '0' || ch > '9' {
					return false
				}
			}
		}
		return true
	}
	return false
}
