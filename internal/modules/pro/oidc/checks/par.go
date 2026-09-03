package checks

import "idenaro/internal/finding"

// PAR returns a finding when the PAR endpoint is absent from OIDC discovery,
// or an INFO finding when PAR is properly supported.
func PAR(host, parEndpoint string) []finding.Finding {
	if parEndpoint != "" {
		f := finding.NewFinding(moduleName, host,
			"Pushed Authorization Requests (PAR) supported",
			"The IdP advertises a PAR endpoint (RFC 9126). Authorization parameters are moved "+
				"from the browser URL to a server-to-server back channel, preventing parameter "+
				"tampering, request forgery, and exposure in browser history or logs.",
			finding.Info,
		)
		f.ID = "oidc-par-ok"
		f.Evidence = []string{"pushed_authorization_request_endpoint: " + parEndpoint}
		f.Confidence = "HIGH"
		f.Tags = []string{"oidc", "iam"}
		return []finding.Finding{f}
	}
	f := finding.NewFinding(moduleName, host,
		"Pushed Authorization Requests (PAR) not supported",
		"PAR (RFC 9126) moves authorization parameters from the front channel (URL) to a "+
			"server-to-server back channel, preventing parameter tampering and request forgery. "+
			"Its absence means all authorization parameters are passed as URL query parameters "+
			"visible in logs and browser history.",
		finding.Info,
	)
	f.ID = "oidc-par"
	f.Evidence = []string{"pushed_authorization_request_endpoint: absent"}
	f.Confidence = "MEDIUM"
	f.Recommendation = "Consider enabling PAR for high-security authorization flows."
	f.Tags = []string{"oidc", "iam"}
	return []finding.Finding{f}
}
