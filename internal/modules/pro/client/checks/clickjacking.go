package checks

import (
	"fmt"
	"net/http"
	"strings"

	"idenaro/internal/finding"
)

// Clickjacking analyses the X-Frame-Options and CSP frame-ancestors headers on
// the login page response and returns findings about clickjacking exposure.
func Clickjacking(host, pageURL string, resp *http.Response) []finding.Finding {
	xfo := resp.Header.Get("X-Frame-Options")
	csp := resp.Header.Get("Content-Security-Policy")

	hasXFO := xfo != ""
	hasFrameAncestors := strings.Contains(strings.ToLower(csp), "frame-ancestors")

	if hasXFO || hasFrameAncestors {
		evidence := []string{}
		if hasXFO {
			evidence = append(evidence, fmt.Sprintf("X-Frame-Options: %s", xfo))
		}
		if hasFrameAncestors {
			for _, directive := range strings.Split(csp, ";") {
				if strings.Contains(strings.ToLower(directive), "frame-ancestors") {
					evidence = append(evidence, fmt.Sprintf("CSP: %s", strings.TrimSpace(directive)))
				}
			}
		}
		f := finding.NewFinding(moduleName, host,
			"Login page protected against clickjacking",
			fmt.Sprintf("The auth page at %s sets framing restrictions that prevent embedding "+
				"in an iframe on untrusted origins.", pageURL),
			finding.Info,
		)
		f.Evidence = evidence
		f.Confidence = "HIGH"
		f.NIS2Articles = []string{NIS2Clickjack}
		f.Tags = []string{moduleName, "client-clickjacking"}
		return []finding.Finding{f}
	}

	f := finding.NewFinding(moduleName, host,
		"Login page missing clickjacking protection",
		fmt.Sprintf("The auth page at %s sets neither X-Frame-Options nor a CSP frame-ancestors "+
			"directive. An attacker can embed the login form in a transparent iframe to perform "+
			"UI-redressing attacks that steal credentials without the user's awareness.", pageURL),
		finding.Medium,
	)
	f.ID = "headers-xframe"
	f.Evidence = []string{
		fmt.Sprintf("GET %s → HTTP %d", pageURL, resp.StatusCode),
		"X-Frame-Options: absent",
		"Content-Security-Policy: no frame-ancestors directive",
	}
	f.Confidence = "HIGH"
	f.Recommendation = "Add 'X-Frame-Options: DENY' or a CSP directive 'frame-ancestors none' " +
		"to all authentication pages to prevent embedding in iframes."
	f.NIS2Articles = []string{NIS2Clickjack}
	f.Tags = []string{moduleName, "client-clickjacking"}
	return []finding.Finding{f}
}
