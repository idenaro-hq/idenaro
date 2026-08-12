package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

type grantTypeInfo struct {
	title    string
	desc     string
	severity finding.Severity
	docID    string
}

var insecureGrantTypes = map[string]grantTypeInfo{
	"password": {
		"Resource Owner Password Credentials (ROPC) grant enabled",
		"The password grant allows clients to collect user credentials directly. " +
			"This completely bypasses MFA, browser-based authentication, and all " +
			"Conditional Access policies. OAuth 2.1 has deprecated this grant entirely.",
		finding.High,
		"oidc-ropc",
	},
	"urn:ietf:params:oauth:grant-type:device_code": {
		"Device Authorization Grant (device flow) enabled",
		"The device flow is designed for input-constrained devices. On public-facing " +
			"IAM systems it is commonly abused in device code phishing attacks where " +
			"attackers trick users into authorizing attacker-controlled device sessions.",
		finding.Medium,
		"oidc-device-flow",
	},
	"client_credentials": {
		"Client Credentials grant advertised in discovery",
		"The client_credentials grant is for machine-to-machine auth. Its presence in " +
			"the public discovery document confirms server-to-server flows are configured. " +
			"Verify no public clients use this grant and that client secrets are properly secured.",
		finding.Info,
		"",
	},
	"implicit": {
		"Implicit grant type explicitly listed",
		"The implicit grant is deprecated in OAuth 2.1. Tokens are returned in URL fragments " +
			"and are vulnerable to browser history, referrer leakage, and open redirect attacks.",
		finding.Medium,
		"oidc-implicit",
	},
}

type safeGrantCheck struct {
	key   string
	title string
	desc  string
	id    string
}

// safeGrantChecks lists dangerous grant types that should NOT be present.
// When absent, an INFO finding is emitted confirming the check was performed.
var safeGrantChecks = []safeGrantCheck{
	{
		"password",
		"ROPC (password) grant not advertised",
		"The Resource Owner Password Credentials grant is not listed in grant_types_supported. " +
			"This reduces the risk of credential-harvesting attacks and ensures MFA and Conditional Access are not bypassed.",
		"oidc-ropc-ok",
	},
	{
		"urn:ietf:params:oauth:grant-type:device_code",
		"Device Authorization Grant not advertised",
		"The device flow grant is not listed in grant_types_supported, " +
			"reducing exposure to device code phishing attacks targeting end users.",
		"oidc-device-flow-ok",
	},
	{
		"implicit",
		"Implicit grant not explicitly listed",
		"The deprecated implicit grant is not listed in grant_types_supported, " +
			"reducing token leakage risk via URL fragments and browser history.",
		"oidc-implicit-grant-ok",
	},
}

// GrantTypes checks grant_types_supported for deprecated or dangerous grant types.
func GrantTypes(host string, supported []string) []finding.Finding {
	var findings []finding.Finding
	for _, gt := range supported {
		if info, bad := insecureGrantTypes[gt]; bad {
			f := finding.NewFinding(moduleName, host, info.title, info.desc, info.severity)
			if info.docID != "" {
				f.ID = info.docID
			}
			f.Evidence = []string{fmt.Sprintf("grant_types_supported includes: %q", gt)}
			f.Confidence = "HIGH"
			f.Recommendation = "Disable legacy grants unless strictly required. Never use ROPC in modern deployments."
			f.Tags = []string{"oidc", "iam"}
			findings = append(findings, f)
		}
	}

	if len(supported) > 0 {
		supportedStr := strings.Join(supported, ", ")
		for _, sc := range safeGrantChecks {
			found := false
			for _, g := range supported {
				if g == sc.key {
					found = true
					break
				}
			}
			if !found {
				f := finding.NewFinding(moduleName, host, sc.title, sc.desc, finding.Info)
				f.ID = sc.id
				f.Evidence = []string{fmt.Sprintf("grant_types_supported: %s", supportedStr)}
				f.Confidence = "HIGH"
				f.Recommendation = "No action required."
				f.Tags = []string{"oidc", "iam"}
				findings = append(findings, f)
			}
		}
	}

	return findings
}
