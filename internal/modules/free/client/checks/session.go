package checks

import (
	"fmt"
	"net/http"

	"idenaro/internal/finding"
)

// SessionCookieFlags checks a single cookie for missing HttpOnly, Secure, and SameSite flags.
// pageURL is the URL where the cookie was observed.
func SessionCookieFlags(host, pageURL string, cookie *http.Cookie) []finding.Finding {
	var findings []finding.Finding

	if !cookie.HttpOnly {
		f := finding.NewFinding(moduleName, host,
			fmt.Sprintf("Session cookie %q missing HttpOnly flag", cookie.Name),
			fmt.Sprintf("Cookie %q set by %s is accessible via JavaScript. "+
				"Any XSS vulnerability on this domain allows direct cookie exfiltration.", cookie.Name, pageURL),
			finding.Medium,
		)
		f.ID = "cookies-httponly"
		f.Evidence = []string{
			fmt.Sprintf("Set-Cookie: %s (HttpOnly absent)", cookie.Name),
			fmt.Sprintf("Source: %s", pageURL),
		}
		f.Confidence = "HIGH"
		f.Recommendation = "Set the HttpOnly flag on all session and auth cookies to prevent JavaScript access."
		f.NIS2Articles = []string{NIS2SessionVal}
		f.Tags = []string{moduleName, "client-session"}
		findings = append(findings, f)
	}

	if !cookie.Secure {
		f := finding.NewFinding(moduleName, host,
			fmt.Sprintf("Session cookie %q missing Secure flag", cookie.Name),
			fmt.Sprintf("Cookie %q set by %s will be transmitted over unencrypted HTTP, "+
				"exposing the token to network interception.", cookie.Name, pageURL),
			finding.Medium,
		)
		f.ID = "cookies-secure"
		f.Evidence = []string{
			fmt.Sprintf("Set-Cookie: %s (Secure absent)", cookie.Name),
			fmt.Sprintf("Source: %s", pageURL),
		}
		f.Confidence = "HIGH"
		f.Recommendation = "Set the Secure flag on all session and auth cookies to restrict transmission to HTTPS."
		f.NIS2Articles = []string{NIS2SessionVal}
		f.Tags = []string{moduleName, "client-session"}
		findings = append(findings, f)
	}

	// SameSiteDefaultMode means no SameSite attribute was set at all.
	if cookie.SameSite == http.SameSiteDefaultMode {
		f := finding.NewFinding(moduleName, host,
			fmt.Sprintf("Session cookie %q missing SameSite attribute", cookie.Name),
			fmt.Sprintf("Cookie %q set by %s has no SameSite attribute. Without SameSite=Strict, "+
				"the browser includes this cookie in cross-site requests, enabling CSRF.", cookie.Name, pageURL),
			finding.Low,
		)
		f.ID = "cookies-samesite"
		f.Evidence = []string{
			fmt.Sprintf("Set-Cookie: %s (SameSite absent)", cookie.Name),
			fmt.Sprintf("Source: %s", pageURL),
		}
		f.Confidence = "HIGH"
		f.Recommendation = "Set SameSite=Strict on all session and auth cookies."
		f.NIS2Articles = []string{NIS2SessionVal}
		f.Tags = []string{moduleName, "client-session"}
		findings = append(findings, f)
	}

	return findings
}

// NoSessionCookies builds an informational finding when no cookies were observed on auth pages.
// probed is the list of evidence strings describing what was probed.
func NoSessionCookies(host string, probed []string) finding.Finding {
	f := finding.NewFinding(moduleName, host,
		"No session cookies observed on auth pages",
		"GET requests to common auth pages returned no Set-Cookie headers. "+
			"This is expected when the application only issues cookies after a complete "+
			"POST/redirect login flow - bare GET probing cannot verify cookie flags in that case.",
		finding.Info,
	)
	f.ID = "client-no-cookies"
	f.Evidence = probed
	f.Confidence = "MEDIUM"
	f.NIS2Articles = []string{NIS2SessionVal}
	f.Tags = []string{moduleName, "client-session"}
	return f
}
