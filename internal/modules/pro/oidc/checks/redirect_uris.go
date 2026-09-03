package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// RedirectURIs checks registered redirect_uris for wildcards, HTTP (non-localhost),
// localhost URIs, and raw IP addresses.
func RedirectURIs(host string, uris []string) []finding.Finding {
	var findings []finding.Finding

	if len(uris) == 0 {
		return nil
	}

	for _, uri := range uris {
		uriLower := strings.ToLower(uri)

		if strings.Contains(uri, "*") {
			f := finding.NewFinding(moduleName, host,
				"Wildcard redirect_uri registered",
				"A wildcard in redirect_uri allows authorization codes to be redirected to "+
					"any matching URL, enabling token theft via open redirect. "+
					"An attacker can craft a login URL that delivers the auth code to an attacker-controlled endpoint.",
				finding.High,
			)
			f.ID = "oidc-wildcard-redirect"
			f.Evidence = []string{fmt.Sprintf("redirect_uri: %s", uri)}
			f.Confidence = "HIGH"
			f.Recommendation = "Register only exact redirect URIs. Never use wildcards."
			f.Tags = []string{"oidc", "iam"}
			findings = append(findings, f)
		}

		if strings.HasPrefix(uriLower, "http://") &&
			!strings.Contains(uriLower, "localhost") &&
			!strings.Contains(uriLower, "127.0.0.1") {
			f := finding.NewFinding(moduleName, host,
				"HTTP redirect_uri registered (non-localhost)",
				fmt.Sprintf("The redirect_uri %q uses HTTP. Authorization codes delivered to HTTP "+
					"endpoints are visible to network observers and proxy logs.", uri),
				finding.High,
			)
			f.ID = "oidc-http-redirect"
			f.Evidence = []string{fmt.Sprintf("redirect_uri: %s", uri)}
			f.Confidence = "HIGH"
			f.Recommendation = "All redirect URIs must use HTTPS except for localhost development URIs."
			f.Tags = []string{"oidc", "iam", "tls"}
			findings = append(findings, f)
		}

		if strings.Contains(uriLower, "localhost") || strings.Contains(uriLower, "127.0.0.1") {
			f := finding.NewFinding(moduleName, host,
				"Localhost redirect_uri registered",
				fmt.Sprintf("A localhost redirect URI (%s) is registered. "+
					"While valid for native/desktop apps, localhost URIs in production IdP configurations "+
					"are often forgotten development artifacts that expand attack surface.", uri),
				finding.Low,
			)
			f.ID = "oidc-localhost-redirect"
			f.Evidence = []string{fmt.Sprintf("redirect_uri: %s", uri)}
			f.Confidence = "MEDIUM"
			f.Recommendation = "Remove localhost redirect URIs from production client registrations."
			f.Tags = []string{"oidc", "iam"}
			findings = append(findings, f)
		}

		if isIPRedirectURI(uri) {
			f := finding.NewFinding(moduleName, host,
				"IP address redirect_uri registered",
				fmt.Sprintf("The redirect_uri %q uses a raw IP address instead of a hostname. "+
					"IP-based redirect URIs bypass hostname-based security controls and are "+
					"harder to audit and revoke.", uri),
				finding.Medium,
			)
			f.ID = "oidc-ip-redirect"
			f.Evidence = []string{fmt.Sprintf("redirect_uri: %s", uri)}
			f.Confidence = "HIGH"
			f.Recommendation = "Use hostname-based redirect URIs. Avoid IP address redirects."
			f.Tags = []string{"oidc", "iam"}
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		f := finding.NewFinding(moduleName, host,
			"All registered redirect URIs are HTTPS and exact-match",
			fmt.Sprintf("All %d registered redirect URI(s) use HTTPS with exact hostnames - no "+
				"wildcards, HTTP, localhost, or IP addresses were found. This prevents authorization "+
				"code interception via open redirect or network observation.", len(uris)),
			finding.Info,
		)
		f.ID = "oidc-redirect-uris-ok"
		f.Evidence = uris
		f.Confidence = "HIGH"
		f.Tags = []string{"oidc", "iam"}
		findings = append(findings, f)
	}

	return findings
}
