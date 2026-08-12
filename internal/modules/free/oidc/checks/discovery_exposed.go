package checks

import "idenaro/internal/finding"

// DiscoveryExposed returns an INFO finding for a reachable OIDC discovery document.
func DiscoveryExposed(host, discoveryURL string) finding.Finding {
	f := finding.NewFinding(moduleName, host,
		"OIDC Discovery Endpoint publicly exposed",
		"The OpenID Connect discovery document is accessible without authentication. "+
			"While expected by the OIDC spec, it exposes the complete IdP configuration.",
		finding.Info,
	)
	f.ID = "oidc-discovery"
	f.Evidence = []string{discoveryURL}
	f.Confidence = "HIGH"
	f.Recommendation = "Expected behavior. Review all exposed configuration for unintended disclosures."
	f.Tags = []string{"oidc", "iam"}
	return f
}
