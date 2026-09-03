package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// AuthPageCSP analyses the Content-Security-Policy on an auth page and flags
// dangerous directives that increase XSS risk on the login surface.
func AuthPageCSP(host, pageURL, cspHeader string) []finding.Finding {
	if cspHeader == "" {
		f := finding.NewFinding(moduleName, host,
			"No Content-Security-Policy on auth page",
			fmt.Sprintf("The auth page at %s has no Content-Security-Policy header. "+
				"Any XSS on this page can directly harvest credentials.", pageURL),
			finding.Medium,
		)
		f.ID = "headers-csp"
		f.Evidence = []string{fmt.Sprintf("GET %s → Content-Security-Policy: absent", pageURL)}
		f.Confidence = "HIGH"
		f.Recommendation = "Deploy a strict CSP on all auth pages. At minimum use " +
			"'default-src self; script-src self; object-src none'."
		f.NIS2Articles = []string{NIS2CSP}
		f.Tags = []string{moduleName, "client-csp"}
		return []finding.Finding{f}
	}

	var findings []finding.Finding
	lower := strings.ToLower(cspHeader)

	if strings.Contains(lower, "unsafe-inline") {
		f := finding.NewFinding(moduleName, host,
			"Auth page CSP allows unsafe-inline scripts",
			fmt.Sprintf("The CSP on %s contains 'unsafe-inline', which allows inline script "+
				"execution and negates most XSS protections on this login surface.", pageURL),
			finding.High,
		)
		f.ID = "csp-unsafe-inline"
		f.Evidence = []string{fmt.Sprintf("Content-Security-Policy: %s", cspHeader)}
		f.Confidence = "HIGH"
		f.Recommendation = "Remove 'unsafe-inline' from script-src. Use nonces or hashes for " +
			"any inline scripts that cannot be refactored."
		f.NIS2Articles = []string{NIS2CSP}
		f.Tags = []string{moduleName, "client-csp"}
		findings = append(findings, f)
	}

	if strings.Contains(lower, "unsafe-eval") {
		f := finding.NewFinding(moduleName, host,
			"Auth page CSP allows unsafe-eval",
			fmt.Sprintf("The CSP on %s contains 'unsafe-eval', enabling dynamic code execution "+
				"via eval() which can be exploited to escalate DOM-based XSS on this auth page.", pageURL),
			finding.Medium,
		)
		f.ID = "csp-unsafe-eval"
		f.Evidence = []string{fmt.Sprintf("Content-Security-Policy: %s", cspHeader)}
		f.Confidence = "HIGH"
		f.Recommendation = "Remove 'unsafe-eval' from script-src on auth pages."
		f.NIS2Articles = []string{NIS2CSP}
		f.Tags = []string{moduleName, "client-csp"}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		f := finding.NewFinding(moduleName, host,
			"Auth page Content-Security-Policy present",
			fmt.Sprintf("The auth page at %s sets a Content-Security-Policy without dangerous "+
				"unsafe-inline or unsafe-eval directives.", pageURL),
			finding.Info,
		)
		f.Evidence = []string{fmt.Sprintf("Content-Security-Policy: %s", cspHeader)}
		f.Confidence = "HIGH"
		f.NIS2Articles = []string{NIS2CSP}
		f.Tags = []string{moduleName, "client-csp"}
		findings = append(findings, f)
	}

	return findings
}
