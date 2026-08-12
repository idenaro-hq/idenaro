package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// EndpointHTTPS checks that all OIDC endpoints and the issuer use HTTPS.
func EndpointHTTPS(host, authEP, tokenEP, jwksURI, userinfoEP, issuer string) []finding.Finding {
	var findings []finding.Finding

	type endpoint struct {
		url  string
		name string
	}
	eps := []endpoint{
		{authEP, "authorization_endpoint"},
		{tokenEP, "token_endpoint"},
		{jwksURI, "jwks_uri"},
		{userinfoEP, "userinfo_endpoint"},
	}

	httpsCount := 0
	checkedCount := 0
	for _, ep := range eps {
		if ep.url == "" {
			continue
		}
		checkedCount++
		if !strings.HasPrefix(ep.url, "https://") {
			f := finding.NewFinding(moduleName, host,
				fmt.Sprintf("%s does not use HTTPS", ep.name),
				fmt.Sprintf("The %s (%s) is served over HTTP. This exposes auth codes, "+
					"tokens, and user data to interception.", ep.name, ep.url),
				finding.High,
			)
			f.ID = "oidc-endpoint-https"
			f.Evidence = []string{fmt.Sprintf("%s: %s", ep.name, ep.url)}
			f.Confidence = "HIGH"
			f.Recommendation = "All OIDC endpoints must be served exclusively over TLS."
			f.Tags = []string{"oidc", "iam", "tls"}
			findings = append(findings, f)
		} else {
			httpsCount++
		}
	}

	issuerHTTPS := issuer != "" && strings.HasPrefix(issuer, "https://")
	if issuer != "" && !issuerHTTPS {
		f := finding.NewFinding(moduleName, host,
			"OIDC issuer does not use HTTPS",
			fmt.Sprintf("The issuer %q does not use HTTPS. Per RFC 8414 the issuer must be an https:// URI.", issuer),
			finding.High,
		)
		f.ID = "oidc-issuer-https"
		f.Evidence = []string{fmt.Sprintf("issuer: %s", issuer)}
		f.Confidence = "HIGH"
		f.Recommendation = "Set the issuer to an https:// URI."
		f.Tags = []string{"oidc", "iam", "tls"}
		findings = append(findings, f)
	}

	if checkedCount > 0 && httpsCount == checkedCount && issuerHTTPS {
		f := finding.NewFinding(moduleName, host,
			"All OIDC endpoints and issuer use HTTPS",
			"All advertised OIDC endpoints (authorization, token, JWKS, userinfo) and the issuer URI use HTTPS, "+
				"ensuring tokens and authorization codes are protected from interception in transit.",
			finding.Info,
		)
		f.ID = "oidc-endpoint-https-ok"
		f.Evidence = []string{
			fmt.Sprintf("issuer: %s", issuer),
			fmt.Sprintf("authorization_endpoint: %s", authEP),
			fmt.Sprintf("token_endpoint: %s", tokenEP),
		}
		f.Confidence = "HIGH"
		f.Recommendation = "No action required."
		f.Tags = []string{"oidc", "iam", "tls"}
		findings = append(findings, f)
	}

	return findings
}
