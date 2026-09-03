package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

var mixedContentPatterns = []string{`src="http://`, `href="http://`, `action="http://`, `url('http://`}

// MixedContent scans the HTML body of an HTTPS page for HTTP resource references.
func MixedContent(host, pageURL, bodyStr string) []finding.Finding {
	lower := strings.ToLower(bodyStr)
	for _, pat := range mixedContentPatterns {
		if strings.Contains(lower, pat) {
			f := finding.NewFinding(moduleName, host,
				"Mixed content detected on auth page",
				"The HTTPS login page references HTTP resources. Mixed content is blocked "+
					"by modern browsers, may cause broken functionality, and can expose "+
					"resources to interception or substitution.",
				finding.Medium,
			)
			f.ID = "tls-mixed-content"
			f.Evidence = []string{fmt.Sprintf("HTTP resource reference pattern %q found in page source", pat)}
			f.Confidence = "MEDIUM"
			f.Recommendation = "Replace all HTTP resource references with HTTPS equivalents. " +
				"Use protocol-relative URLs or absolute HTTPS URLs."
			f.Tags = []string{"tls", "iam", "headers"}
			return []finding.Finding{f}
		}
	}
	return nil
}
