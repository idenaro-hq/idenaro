package scoring

import "idenaro/internal/finding"

// chainRules is the full set of combination rules evaluated after all modules
// have run. Add new rules here; no other files need changing.
var chainRules = []ChainRule{
	{
		DocID: "chain-admin-session",
		Name:  "Exposed admin panel + missing authentication controls",
		Description: "An admin panel is publicly accessible AND session security controls are weak. " +
			"Together, these mean an attacker who gains session access has an easy path to full admin.",
		RequiredTagSlots:    [][]string{{"admin-exposure"}, {"cookies", "headers"}},
		MinMatchingFindings: 2,
		ChainSeverity:       finding.Critical,
	},
	{
		DocID: "chain-implicit-csp",
		Name:  "Implicit flow + weak CSP on login page",
		Description: "OIDC implicit flow is enabled AND the login page has a weak Content Security Policy. " +
			"An XSS vulnerability on the login page can steal access tokens transmitted via URL fragment.",
		RequiredTagSlots:    [][]string{{"oidc"}, {"csp", "headers"}},
		MinMatchingFindings: 2,
		ChainSeverity:       finding.High,
	},
	{
		DocID: "chain-mfa-admin",
		Name:  "Missing MFA + exposed admin endpoint",
		Description: "No MFA indicators are detected AND an administrative endpoint is publicly accessible. " +
			"A single compromised password grants full administrative access.",
		RequiredTagSlots:    [][]string{{"mfa"}, {"admin-exposure"}},
		MinMatchingFindings: 2,
		ChainSeverity:       finding.Critical,
	},
	{
		DocID: "chain-hsts-cookies",
		Name:  "Missing HSTS + insecure cookie flags",
		Description: "HSTS is absent AND session cookies lack the Secure flag. " +
			"An SSL stripping attack can intercept session tokens over HTTP.",
		RequiredTagSlots:    [][]string{{"headers"}, {"cookies"}},
		MinMatchingFindings: 2,
		ChainSeverity:       finding.High,
	},
	{
		DocID: "chain-cors-api",
		Name:  "CORS misconfiguration + sensitive API endpoint",
		Description: "CORS is misconfigured on an auth-sensitive endpoint. " +
			"Combined with any authenticated session, this enables cross-site request forgery at scale.",
		RequiredTagSlots:    [][]string{{"cors"}, {"iam", "endpoints"}},
		MinMatchingFindings: 2,
		ChainSeverity:       finding.High,
	},
	{
		DocID: "chain-multi-endpoints",
		Name:  "Multiple debug/admin endpoints exposed",
		Description: "Three or more sensitive endpoints are publicly accessible. " +
			"This indicates a systemic lack of deployment hardening, not an isolated oversight.",
		RequiredTagSlots:    [][]string{{"admin-exposure"}, {"endpoints"}},
		MinMatchingFindings: 3,
		ChainSeverity:       finding.High,
	},
	{
		DocID: "chain-redirect-oidc",
		Name:  "Open redirect + OIDC flow active",
		Description: "An open redirect is present AND OIDC is configured. " +
			"Open redirects in OIDC authorization flows allow stealing authorization codes and tokens.",
		RequiredTagSlots:    [][]string{{"redirects"}, {"oidc"}},
		MinMatchingFindings: 2,
		ChainSeverity:       finding.High,
	},
	{
		DocID: "chain-enum-mfa",
		Name:  "User enumeration + no MFA",
		Description: "User enumeration is possible AND MFA is absent or not enforced. " +
			"Enumerated usernames can be directly used in targeted credential attacks without MFA friction.",
		RequiredTagSlots:    [][]string{{"enumeration"}, {"mfa"}},
		MinMatchingFindings: 2,
		ChainSeverity:       finding.High,
	},
	{
		DocID: "chain-scim-iac",
		Name:  "SCIM exposed + weak access control signals",
		Description: "A SCIM provisioning endpoint is accessible AND access control weaknesses are present. " +
			"SCIM provides full CRUD over user identities - combined with other IAM weaknesses, this is critical.",
		RequiredTagSlots:    [][]string{{"scim"}, {"iam", "admin-exposure"}},
		MinMatchingFindings: 2,
		ChainSeverity:       finding.Critical,
	},
}
