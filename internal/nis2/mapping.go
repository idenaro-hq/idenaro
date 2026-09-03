package nis2

// articlesByTag maps finding tags to the relevant NIS2 directive articles.
// Sub-paragraphs of Art. 21(2):
//
//	(a) Risk analysis and information system security policies
//	(b) Incident handling
//	(c) Business continuity, backup management and disaster recovery
//	(d) Supply chain security
//	(e) Security in network and information systems acquisition, development and maintenance
//	(f) Policies to assess effectiveness of cybersecurity risk-management measures
//	(g) Basic cyber hygiene practices and cybersecurity training
//	(h) Policies and procedures regarding the use of cryptography and encryption
//	(i) Human resources security, access control policies and asset management
//	(j) Multi-factor or continuous authentication and secured communications
//
// Each tag maps to exactly one primary NIS2 article. One-article-per-tag prevents
// the shotgun effect where a finding with three tags references five unrelated articles.
var articlesByTag = map[string]string{
	// Identity & access control - Art. 21(2)(i) is the canonical access-control article.
	"iam":            "21-2-i",
	"admin-exposure": "21-2-i",
	"enumeration":    "21-2-i",
	"scim":           "21-2-i",
	"lifecycle":      "21-2-i",
	"zero-trust":     "21-2-i",

	// Authentication protocols - Art. 21(2)(j) explicitly names MFA and secured auth.
	"mfa":  "21-2-j",
	"oidc": "21-2-j",
	"saml": "21-2-j",

	// Cryptography - Art. 21(2)(h) covers keys, certs, and token secrets.
	"tls":        "21-2-h",
	"encryption": "21-2-h",
	"tokens":     "21-2-h",

	// Secure development & configuration - Art. 21(2)(e) covers web security controls.
	"headers":   "21-2-e",
	"cookies":   "21-2-e",
	"cors":      "21-2-e",
	"csp":       "21-2-e",
	"redirects": "21-2-e",
	"endpoints": "21-2-e",

	// Client / relying-party application checks.
	// Token validation and CSRF/state relate to access control (i); session cookies
	// and CORS relate to communication security and secure configuration (h / e).
	"client-token-validation": "21-2-j", // authentication enforcement at the relying party
	"client-session":          "21-2-e", // session cookie flags (Secure, HttpOnly, SameSite)
	"client-cors":             "21-2-e", // cross-origin policy on relying-party endpoints
	"client-csrf":             "21-2-i", // CSRF/state-param and open-redirect on callbacks

	// Compound risk - a chain finding indicates a risk-analysis gap per Art. 21(2)(a).
	"chain": "21-2-a",
}

// Lookup returns deduplicated NIS2 article reference strings for the given tags (English).
func Lookup(tags []string) []string {
	return lookupLocalized(tags, "en")
}

// LookupDE returns deduplicated NIS2 article reference strings for the given tags (German).
func LookupDE(tags []string) []string {
	return lookupLocalized(tags, "de")
}

// LookupLocalized returns article references in the requested language ("en" or "de").
func LookupLocalized(tags []string, lang string) []string {
	return lookupLocalized(tags, lang)
}

func lookupLocalized(tags []string, lang string) []string {
	seen := make(map[string]bool)
	var refs []string

	for _, tag := range tags {
		id, ok := articlesByTag[tag]
		if !ok {
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true

		art, found := FindByID(id)
		if !found {
			continue
		}
		if lang == "de" {
			refs = append(refs, "Art. 21 (2)("+string(id[len(id)-1])+") - "+art.TitleDE)
		} else {
			refs = append(refs, "Art. 21 (2)("+string(id[len(id)-1])+") - "+art.Title)
		}
	}
	return refs
}
