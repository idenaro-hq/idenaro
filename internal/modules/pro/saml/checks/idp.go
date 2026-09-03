package checks

import (
	"fmt"

	"idenaro/internal/finding"
)

// IDP checks IdP-specific SAML metadata for signing requirement and certificate issues.
func IDP(host, wantAuthnRequestsSigned string, keyDescs []KeyDescriptor) []finding.Finding {
	var findings []finding.Finding

	want := wantAuthnRequestsSigned
	if want == "false" || want == "" {
		f := finding.NewFinding(moduleName, host,
			"SAML IdP does not require signed AuthnRequests",
			"WantAuthnRequestsSigned=false (or absent) means the IdP accepts unsigned authentication "+
				"requests. Attackers can forge authentication requests, manipulate NameID formats, "+
				"ForceAuthn flags, and requested attributes. This also enables IdP-initiated SSO "+
				"attacks where the flow starts without a verifiable SP request.",
			finding.Medium,
		)
		f.ID = "saml-unsigned-authn"
		f.Evidence = []string{fmt.Sprintf(`WantAuthnRequestsSigned="%s" in IDPSSODescriptor`, want)}
		f.Confidence = "HIGH"
		f.Recommendation = "Set WantAuthnRequestsSigned=true and enforce request signature validation."
		f.Tags = []string{"saml", "iam"}
		findings = append(findings, f)

		f2 := finding.NewFinding(moduleName, host,
			"IdP-initiated SSO likely enabled",
			"Because WantAuthnRequestsSigned is not enforced, the IdP can initiate SSO flows "+
				"without a prior AuthnRequest from the SP. IdP-initiated SSO bypasses CSRF protections "+
				"built into the SP-initiated flow (state parameter, RelayState validation) and is "+
				"commonly abused in session fixation and account takeover attacks.",
			finding.Medium,
		)
		f2.Evidence = []string{
			fmt.Sprintf(`WantAuthnRequestsSigned="%s"`, want),
			"No signed AuthnRequest requirement - IdP can push assertions unprompted",
		}
		f2.Confidence = "MEDIUM"
		f2.Recommendation = "Disable IdP-initiated SSO if not required. If needed, implement strict " +
			"RelayState validation and CSRF tokens at the SP."
		f2.Tags = []string{"saml", "iam"}
		findings = append(findings, f2)
	} else if want == "true" {
		f := finding.NewFinding(moduleName, host,
			"SAML IdP requires signed AuthnRequests",
			"WantAuthnRequestsSigned=true means the IdP validates that all incoming authentication "+
				"requests carry a valid SP signature. This prevents request forgery and blocks "+
				"IdP-initiated SSO attacks where unsigned requests could manipulate NameID formats "+
				"or ForceAuthn flags.",
			finding.Info,
		)
		f.ID = "saml-idp-signing-ok"
		f.Evidence = []string{fmt.Sprintf(`WantAuthnRequestsSigned="%s" in IDPSSODescriptor`, want)}
		f.Confidence = "HIGH"
		f.Tags = []string{"saml", "iam"}
		findings = append(findings, f)
	}

	findings = append(findings, KeyDescriptors(host, "IdP", keyDescs)...)
	return findings
}
