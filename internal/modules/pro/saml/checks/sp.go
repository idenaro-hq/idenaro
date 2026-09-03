package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// ACSEndpoint is a minimal view of an AssertionConsumerService element.
type ACSEndpoint struct {
	Location string
}

// SP checks SP-specific SAML metadata for signing requirements, encryption key
// presence, ACS endpoint HTTPS, and certificate issues.
func SP(
	host string,
	wantAssertionsSigned, authnRequestsSigned string,
	acsEndpoints []ACSEndpoint,
	keyDescs []KeyDescriptor,
) []finding.Finding {
	var findings []finding.Finding

	if strings.EqualFold(wantAssertionsSigned, "false") {
		f := finding.NewFinding(moduleName, host,
			"SAML SP does not require signed assertions",
			"WantAssertionsSigned=false means the SP accepts unsigned SAML assertions. "+
				"An attacker who can intercept or inject assertions can authenticate as any user "+
				"by crafting a valid-looking (but unsigned) assertion.",
			finding.High,
		)
		f.ID = "saml-sp-unsigned-assertions"
		f.Evidence = []string{`WantAssertionsSigned="false" in SPSSODescriptor`}
		f.Confidence = "HIGH"
		f.Recommendation = "Set WantAssertionsSigned=true and enforce assertion signature validation."
		f.Tags = []string{"saml", "iam"}
		findings = append(findings, f)
	}

	if strings.EqualFold(authnRequestsSigned, "false") || authnRequestsSigned == "" {
		f := finding.NewFinding(moduleName, host,
			"SAML SP does not sign AuthnRequests",
			"The SP does not sign outbound authentication requests. "+
				"Unsigned requests allow man-in-the-middle manipulation of NameID format, "+
				"ForceAuthn flags, and requested attributes.",
			finding.Medium,
		)
		f.ID = "saml-sp-unsigned-authn"
		f.Evidence = []string{fmt.Sprintf(`AuthnRequestsSigned="%s" in SPSSODescriptor`, authnRequestsSigned)}
		f.Confidence = "MEDIUM"
		f.Recommendation = "Sign AuthnRequests from the SP. Ensure the IdP validates the signature."
		f.Tags = []string{"saml", "iam"}
		findings = append(findings, f)
	}

	hasEncKey := false
	for _, kd := range keyDescs {
		if strings.EqualFold(kd.Use, "encryption") {
			hasEncKey = true
			break
		}
	}
	if !hasEncKey {
		f := finding.NewFinding(moduleName, host,
			"SAML SP has no encryption key descriptor",
			"The SP metadata has no encryption key. Assertions cannot be encrypted, "+
				"meaning SAML attributes (including user identity and role claims) are transmitted "+
				"in plaintext within the SAML response. If transport security is degraded, "+
				"or if the assertion is logged, attributes are exposed.",
			finding.Medium,
		)
		f.ID = "saml-no-encryption-key"
		f.Evidence = []string{"No KeyDescriptor with use=encryption in SPSSODescriptor"}
		f.Confidence = "HIGH"
		f.Recommendation = "Add an encryption key descriptor and configure the IdP to encrypt assertions."
		f.Tags = []string{"saml", "iam"}
		findings = append(findings, f)
	}

	for _, acs := range acsEndpoints {
		if acs.Location != "" && !strings.HasPrefix(acs.Location, "https://") {
			f := finding.NewFinding(moduleName, host,
				"SAML ACS endpoint does not use HTTPS",
				fmt.Sprintf("The AssertionConsumerService at %q uses HTTP. "+
					"SAML assertions posted to this endpoint are transmitted in cleartext, "+
					"exposing user identity and session establishment to interception.", acs.Location),
				finding.High,
			)
			f.ID = "saml-acs-http"
			f.Evidence = []string{fmt.Sprintf("ACS Location: %s", acs.Location)}
			f.Confidence = "HIGH"
			f.Recommendation = "All ACS endpoints must use HTTPS."
			f.Tags = []string{"saml", "iam", "tls"}
			findings = append(findings, f)
		}
	}

	findings = append(findings, KeyDescriptors(host, "SP", keyDescs)...)

	wantSigned := !strings.EqualFold(wantAssertionsSigned, "false")
	authnSigned := strings.EqualFold(authnRequestsSigned, "true")
	if wantSigned && authnSigned && hasEncKey && len(acsEndpoints) > 0 {
		f := finding.NewFinding(moduleName, host,
			"SAML SP enforces assertion signing, request signing, and encryption",
			"The SP metadata requires signed assertions (WantAssertionsSigned=true), signs outbound "+
				"AuthnRequests (AuthnRequestsSigned=true), and publishes an encryption key descriptor. "+
				"Assertions are protected against forgery and eavesdropping.",
			finding.Info,
		)
		f.ID = "saml-sp-signing-ok"
		f.Evidence = []string{
			fmt.Sprintf("WantAssertionsSigned: %s", wantAssertionsSigned),
			fmt.Sprintf("AuthnRequestsSigned: %s", authnRequestsSigned),
			"Encryption KeyDescriptor: present",
		}
		f.Confidence = "HIGH"
		f.Tags = []string{"saml", "iam"}
		findings = append(findings, f)
	}

	return findings
}
