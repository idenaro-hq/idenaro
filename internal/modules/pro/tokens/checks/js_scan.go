package checks

import (
	"fmt"
	"regexp"

	"idenaro/internal/finding"
)

// Pattern describes a single JavaScript security check.
type Pattern struct {
	Re        *regexp.Regexp
	Label     string
	Severity  finding.Severity
	Recommend string
	DocID     string
}

// JSPatterns are the security patterns scanned in JavaScript sources.
var JSPatterns = []Pattern{
	{
		Re:        regexp.MustCompile(`(?i)(access_token|accessToken)\s*[:=]\s*["'][A-Za-z0-9\-_\.]+["']`),
		Label:     "Access token value hardcoded in JavaScript",
		Severity:  finding.Critical,
		Recommend: "Never hardcode access tokens. Use short-lived tokens fetched at runtime via secure auth flows.",
		DocID:     "tokens-access-token",
	},
	{
		Re:        regexp.MustCompile(`(?i)(refresh_token|refreshToken)\s*[:=]\s*["'][A-Za-z0-9\-_\.]+["']`),
		Label:     "Refresh token value hardcoded in JavaScript",
		Severity:  finding.Critical,
		Recommend: "Never hardcode refresh tokens. They grant long-lived access and must be stored server-side.",
		DocID:     "tokens-access-token",
	},
	{
		Re:        regexp.MustCompile(`(?i)(id_token|idToken)\s*[:=]\s*["'][A-Za-z0-9\-_\.]+["']`),
		Label:     "ID token value hardcoded in JavaScript",
		Severity:  finding.High,
		Recommend: "ID tokens must not be embedded in frontend code.",
		DocID:     "tokens-access-token",
	},
	{
		Re:        regexp.MustCompile(`(?i)(client_secret|clientSecret)\s*[:=]\s*["'][A-Za-z0-9\-_\+/=]{8,}["']`),
		Label:     "OAuth client secret exposed in JavaScript",
		Severity:  finding.Critical,
		Recommend: "Client secrets must never appear in frontend code. Use a backend-for-frontend (BFF) pattern.",
		DocID:     "tokens-client-secret",
	},
	{
		Re:        regexp.MustCompile(`(?i)(client_id|clientId)\s*[:=]\s*["'][A-Za-z0-9\-_\.]{8,}["']`),
		Label:     "OAuth client_id exposed in JavaScript",
		Severity:  finding.Info,
		Recommend: "client_id in public JS is expected for SPAs. Verify it is a public client with no secret.",
		DocID:     "tokens-client-id",
	},
	{
		Re:        regexp.MustCompile(`(?i)(issuer|authority)\s*[:=]\s*["'](https?://[^"']+)["']`),
		Label:     "OIDC issuer/authority URL found in JavaScript",
		Severity:  finding.Info,
		Recommend: "Expected for SPA auth config. Verify the issuer is the intended production IdP.",
	},
	{
		Re:        regexp.MustCompile(`(?i)localStorage\.setItem\s*\(\s*["'][^"']*(?:token|auth|session|jwt)[^"']*["']`),
		Label:     "Auth token stored in localStorage",
		Severity:  finding.High,
		Recommend: "localStorage is accessible to any JavaScript on the page. Use HttpOnly cookies or sessionStorage with CSP.",
		DocID:     "tokens-localstorage",
	},
	{
		Re:        regexp.MustCompile(`(?i)sessionStorage\.setItem\s*\(\s*["'][^"']*(?:token|auth|jwt)[^"']*["']`),
		Label:     "Auth token stored in sessionStorage",
		Severity:  finding.Medium,
		Recommend: "sessionStorage is accessible to JavaScript. Prefer HttpOnly cookies for session tokens.",
		DocID:     "tokens-sessionstorage",
	},
	{
		Re:        regexp.MustCompile(`(?i)window\.(access_token|id_token|refresh_token|authToken)\s*=`),
		Label:     "Auth token assigned to global window object",
		Severity:  finding.High,
		Recommend: "Global window token variables are accessible to any script. Use closures or secure storage patterns.",
		DocID:     "tokens-window-global",
	},
	{
		Re:        regexp.MustCompile(`(?i)(apiKey|api_key)\s*[:=]\s*["'][A-Za-z0-9\-_]{16,}["']`),
		Label:     "API key exposed in JavaScript",
		Severity:  finding.Medium,
		Recommend: "API keys in frontend JS are visible to all users. Use server-side proxying for API calls requiring keys.",
		DocID:     "tokens-api-key",
	},
	{
		Re:        regexp.MustCompile(`(?i)(tenant(?:Id|_id)|tenantID)\s*[:=]\s*["'][A-Za-z0-9\-]{8,}["']`),
		Label:     "Tenant ID exposed in JavaScript",
		Severity:  finding.Info,
		Recommend: "Tenant IDs in frontend code aid attacker reconnaissance of cloud identity configuration.",
	},
}

// ScanContent scans a JavaScript string for all patterns and appends findings
// to seen (keyed by label) to avoid duplicates across multiple files.
func ScanContent(content, source, host string, seen map[string]bool) []finding.Finding {
	var findings []finding.Finding

	for _, pat := range JSPatterns {
		match := pat.Re.FindString(content)
		if match == "" {
			continue
		}
		if seen[pat.Label] {
			continue
		}
		seen[pat.Label] = true

		evidence := match
		if len(evidence) > 120 {
			evidence = evidence[:120] + "..."
		}

		f := finding.NewFinding(moduleName, host,
			pat.Label,
			fmt.Sprintf("Pattern detected in JavaScript source (%s).", shortenURL(source)),
			pat.Severity,
		)
		f.Evidence = []string{
			fmt.Sprintf("Source: %s", shortenURL(source)),
			fmt.Sprintf("Match: %s", evidence),
		}
		if pat.DocID != "" {
			f.ID = pat.DocID
		}
		f.Confidence = "MEDIUM"
		f.Recommendation = pat.Recommend
		f.Tags = []string{"tokens", "iam"}
		findings = append(findings, f)
	}

	return findings
}

// Dedup removes duplicate strings from ss.
func Dedup(ss []string) []string { return dedup(ss) }
