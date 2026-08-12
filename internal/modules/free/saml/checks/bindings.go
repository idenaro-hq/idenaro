package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// SSOService is a minimal view of a SingleSignOnService element used to avoid
// importing the parent saml package (which would create a circular dependency).
type SSOService struct {
	Binding  string
	Location string
}

// Bindings checks SSO endpoint HTTPS and reports insecure binding types
// (HTTP-Redirect, SOAP, Artifact).
func Bindings(host string, ssoServices []SSOService) []finding.Finding {
	var findings []finding.Finding
	hasRedirect := false
	hasSOAP := false
	hasArtifact := false

	for _, sso := range ssoServices {
		bl := strings.ToLower(sso.Binding)

		if strings.Contains(bl, "http-redirect") {
			hasRedirect = true
		}
		if strings.Contains(bl, "soap") {
			hasSOAP = true
		}
		if strings.Contains(bl, "artifact") {
			hasArtifact = true
		}

		if sso.Location != "" && !strings.HasPrefix(sso.Location, "https://") {
			f := finding.NewFinding(moduleName, host,
				"SAML SSO endpoint does not use HTTPS",
				fmt.Sprintf("The SingleSignOnService location %q does not use HTTPS. "+
					"SAML assertions transmitted over HTTP are visible to network observers.", sso.Location),
				finding.High,
			)
			f.ID = "saml-sso-http"
			f.Evidence = []string{
				fmt.Sprintf("Binding: %s", sso.Binding),
				fmt.Sprintf("Location: %s", sso.Location),
			}
			f.Confidence = "HIGH"
			f.Recommendation = "All SAML endpoints must use HTTPS."
			f.Tags = []string{"saml", "iam", "tls"}
			findings = append(findings, f)
		}
	}

	if hasRedirect {
		f := finding.NewFinding(moduleName, host,
			"SAML HTTP-Redirect Binding in use",
			"HTTP-Redirect binding transmits SAML messages in URL parameters, exposing them to "+
				"server logs and browser history. HTTP-POST binding is preferred.",
			finding.Low,
		)
		f.ID = "saml-redirect-binding"
		f.Evidence = []string{"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect found in SingleSignOnService"}
		f.Confidence = "HIGH"
		f.Recommendation = "Prefer HTTP-POST binding. HTTP-Redirect is acceptable for requests only, not responses."
		f.Tags = []string{"saml", "iam"}
		findings = append(findings, f)
	}

	if hasSOAP {
		f := finding.NewFinding(moduleName, host,
			"SAML SOAP binding exposed",
			"The SOAP binding is listed in SAML metadata. SOAP bindings are uncommon, "+
				"expand the attack surface, and are rarely required in modern deployments.",
			finding.Low,
		)
		f.ID = "saml-soap-binding"
		f.Evidence = []string{"SOAP binding found in IDPSSODescriptor"}
		f.Confidence = "HIGH"
		f.Recommendation = "Remove SOAP binding unless explicitly required by a federation partner."
		f.Tags = []string{"saml", "iam"}
		findings = append(findings, f)
	}

	if hasArtifact {
		f := finding.NewFinding(moduleName, host,
			"SAML Artifact binding exposed",
			"The Artifact binding requires an additional back-channel resolution step. "+
				"Misconfigured artifact resolution endpoints can be abused for SSRF.",
			finding.Low,
		)
		f.ID = "saml-artifact-binding"
		f.Evidence = []string{"Artifact binding found in IDPSSODescriptor"}
		f.Confidence = "MEDIUM"
		f.Recommendation = "Remove Artifact binding unless specifically required. Audit the artifact resolution endpoint."
		f.Tags = []string{"saml", "iam"}
		findings = append(findings, f)
	}

	if len(findings) == 0 && len(ssoServices) > 0 {
		f := finding.NewFinding(moduleName, host,
			"SAML SSO endpoints use secure bindings and HTTPS",
			"All SingleSignOnService endpoints use HTTPS and no insecure bindings (SOAP, Artifact) "+
				"were found. HTTP-Redirect binding is absent or used only for requests, not responses.",
			finding.Info,
		)
		f.ID = "saml-bindings-ok"
		bindings := make([]string, 0, len(ssoServices))
		for _, sso := range ssoServices {
			bindings = append(bindings, fmt.Sprintf("%s → %s", sso.Binding, sso.Location))
		}
		f.Evidence = bindings
		f.Confidence = "HIGH"
		f.Tags = []string{"saml", "iam"}
		findings = append(findings, f)
	}

	return findings
}
