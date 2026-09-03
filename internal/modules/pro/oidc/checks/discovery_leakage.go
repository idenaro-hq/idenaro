package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

var leakPatterns = []struct {
	pattern string
	label   string
}{
	{"localhost", "localhost reference"},
	{"127.0.0.1", "loopback IP"},
	{"10.", "RFC1918 private IP (10.x)"},
	{"192.168.", "RFC1918 private IP (192.168.x)"},
	{"172.16.", "RFC1918 private IP (172.16.x)"},
	{".internal", "internal DNS suffix"},
	{".local", "mDNS/internal DNS suffix"},
	{".corp", "corporate internal DNS"},
	{".svc.cluster", "Kubernetes service DNS"},
	{"staging", "staging environment reference"},
	{"dev.", "development environment reference"},
	{"test.", "test environment reference"},
}

// DiscoveryLeakage checks the raw discovery document body for internal hostnames
// and environment references that reveal infrastructure details.
func DiscoveryLeakage(host, discoveryURL, bodyStr string) []finding.Finding {
	lower := strings.ToLower(bodyStr)
	for _, lp := range leakPatterns {
		if strings.Contains(lower, strings.ToLower(lp.pattern)) {
			f := finding.NewFinding(moduleName, host,
				fmt.Sprintf("Discovery document contains %s", lp.label),
				fmt.Sprintf("The OIDC discovery document contains a %s (%q). "+
					"Internal infrastructure details in public discovery documents aid attacker "+
					"reconnaissance and often indicate misconfigured deployments.", lp.label, lp.pattern),
				finding.Medium,
			)
			f.ID = "oidc-internal-leak"
			f.Evidence = []string{
				fmt.Sprintf("Pattern %q found in discovery document", lp.pattern),
				"Discovery URL: " + discoveryURL,
			}
			f.Confidence = "HIGH"
			f.Recommendation = "Ensure all OIDC endpoint URLs use public-facing hostnames only. " +
				"Fix reverse proxy configuration to rewrite internal URLs."
			f.Tags = []string{"oidc", "iam"}
			return []finding.Finding{f}
		}
	}

	f := finding.NewFinding(moduleName, host,
		"OIDC discovery document contains no internal infrastructure references",
		"The discovery document was scanned for internal hostnames, RFC1918 IP addresses, "+
			"Kubernetes service DNS, and environment-specific references (staging, dev, test). "+
			"None were found - the document exposes only public-facing URLs.",
		finding.Info,
	)
	f.ID = "oidc-discovery-clean"
	f.Evidence = []string{"Discovery URL: " + discoveryURL}
	f.Confidence = "HIGH"
	f.Tags = []string{"oidc", "iam"}
	return []finding.Finding{f}
}
