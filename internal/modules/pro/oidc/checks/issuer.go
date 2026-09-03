package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// Issuer checks the OIDC issuer field for host mismatch, multi-tenant endpoints,
// and endpoint sprawl across too many domains.
func Issuer(host, targetHost, issuer, authEndpoint, tokenEndpoint, jwksURI, userinfoEndpoint string) []finding.Finding {
	var findings []finding.Finding

	if issuer == "" {
		return nil
	}

	issuerHost := extractHost(issuer)

	if issuerHost != "" &&
		issuerHost != targetHost &&
		!strings.HasSuffix(issuerHost, "."+targetHost) {
		f := finding.NewFinding(moduleName, host,
			"OIDC issuer host mismatch",
			fmt.Sprintf("The discovery document is served from %q but the issuer is %q. "+
				"This often indicates a broken reverse proxy setup, split-DNS misconfiguration, "+
				"or an incomplete migration. Clients that validate the issuer claim will reject "+
				"tokens from this IdP.", targetHost, issuer),
			finding.Medium,
		)
		f.ID = "oidc-issuer-mismatch"
		f.Evidence = []string{
			fmt.Sprintf("Discovery URL host: %s", targetHost),
			fmt.Sprintf("Issuer: %s", issuer),
		}
		f.Confidence = "MEDIUM"
		f.Recommendation = "The issuer must exactly match the URL from which the discovery document is served."
		f.Tags = []string{"oidc", "iam"}
		findings = append(findings, f)
	}

	issuerLower := strings.ToLower(issuer)
	if strings.Contains(issuerLower, "/common/") || strings.Contains(issuerLower, "/organizations/") {
		f := finding.NewFinding(moduleName, host,
			"Multi-tenant issuer endpoint detected - audience confusion risk",
			fmt.Sprintf("The issuer %q uses a multi-tenant endpoint (/common/ or /organizations/). "+
				"Applications that accept tokens from this issuer without validating the tenant ID "+
				"(tid claim) are vulnerable to cross-tenant audience confusion attacks: a valid token "+
				"issued for one tenant can be accepted by applications in a different tenant.", issuer),
			finding.High,
		)
		f.Evidence = []string{fmt.Sprintf("Issuer: %s", issuer)}
		f.Confidence = "HIGH"
		f.Recommendation = "Configure client applications to validate the `tid` claim against your " +
			"expected tenant ID. Never accept tokens from /common/ or /organizations/ without " +
			"tenant-specific audience validation."
		f.Tags = []string{"oidc", "iam"}
		findings = append(findings, f)
	}

	endpointHosts := map[string]bool{issuerHost: true}
	for _, u := range []string{authEndpoint, tokenEndpoint, jwksURI, userinfoEndpoint} {
		if h := extractHost(u); h != "" {
			endpointHosts[h] = true
		}
	}
	if len(endpointHosts) > 2 {
		f := finding.NewFinding(moduleName, host,
			"OIDC endpoints span multiple domains",
			fmt.Sprintf("The OIDC endpoints are spread across %d different hosts: %s. "+
				"This indicates a complex or broken deployment where trust boundaries are unclear.",
				len(endpointHosts), joinKeys(endpointHosts)),
			finding.Low,
		)
		f.ID = "oidc-multi-domain"
		f.Evidence = []string{fmt.Sprintf("Distinct endpoint hosts: %s", joinKeys(endpointHosts))}
		f.Confidence = "MEDIUM"
		f.Recommendation = "Consolidate OIDC endpoints under a single domain where possible."
		f.Tags = []string{"oidc", "iam"}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		f := finding.NewFinding(moduleName, host,
			"OIDC issuer is consistent and single-domain",
			fmt.Sprintf("The issuer %q matches the discovery document host and all OIDC endpoints "+
				"are served from a consistent set of domains. No multi-tenant or cross-domain "+
				"deployment patterns were detected.", issuer),
			finding.Info,
		)
		f.ID = "oidc-issuer-ok"
		f.Evidence = []string{
			fmt.Sprintf("Issuer: %s", issuer),
			fmt.Sprintf("Discovery host: %s", targetHost),
		}
		f.Confidence = "HIGH"
		f.Tags = []string{"oidc", "iam"}
		findings = append(findings, f)
	}

	return findings
}
