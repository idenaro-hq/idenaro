package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// HTTPRedirect returns a finding when an HTTP request gets a 200 OK instead of
// a redirect to HTTPS, or an INFO finding when a proper HTTPS redirect is in place.
func HTTPRedirect(host, httpURL string, statusCode int, location string) []finding.Finding {
	if statusCode >= 300 && statusCode < 400 && strings.HasPrefix(location, "https://") {
		f := finding.NewFinding(moduleName, host,
			"HTTP to HTTPS redirect is in place",
			fmt.Sprintf("The server responds to plain HTTP requests with a %d redirect to HTTPS. "+
				"Users who visit the HTTP URL are automatically upgraded to an encrypted connection.", statusCode),
			finding.Info,
		)
		f.ID = "tls-https-redirect-ok"
		f.Evidence = []string{
			fmt.Sprintf("HTTP %d at %s → %s", statusCode, httpURL, location),
		}
		f.Confidence = "HIGH"
		f.Tags = []string{"tls", "iam", "headers"}
		return []finding.Finding{f}
	}
	if statusCode != 200 {
		return nil
	}
	f := finding.NewFinding(moduleName, host,
		"HTTP endpoint responds without redirecting to HTTPS",
		"The server responds to plain HTTP requests without redirecting to HTTPS. "+
			"Users who visit the HTTP URL will have their session exposed.",
		finding.High,
	)
	f.ID = "tls-no-https-redirect"
	f.Evidence = []string{
		fmt.Sprintf("HTTP %d at %s (no HTTPS redirect)", statusCode, httpURL),
	}
	f.Confidence = "HIGH"
	f.Recommendation = "Redirect all HTTP traffic to HTTPS with a permanent 301 redirect. " +
		"Combine with HSTS to prevent future HTTP access."
	f.Tags = []string{"tls", "iam", "headers"}
	return []finding.Finding{f}
}
