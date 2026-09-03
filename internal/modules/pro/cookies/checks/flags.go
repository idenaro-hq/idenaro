package checks

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"idenaro/internal/finding"
)

// Flags inspects a single cookie for all security flag violations and returns
// one finding per issue found.
func Flags(cookie *http.Cookie, hostName, sourceURL string) []finding.Finding {
	var findings []finding.Finding
	isAuth := IsAuthCookieName(cookie.Name)

	if !cookie.Secure {
		sev := finding.Medium
		if isAuth {
			sev = finding.High
		}
		f := finding.NewFinding(moduleName, hostName,
			fmt.Sprintf("Cookie %q missing Secure flag", cookie.Name),
			fmt.Sprintf("Cookie %q is set without the Secure flag. It will be transmitted over "+
				"unencrypted HTTP connections, exposing the token to network interception.", cookie.Name),
			sev,
		)
		f.ID = "cookies-secure"
		f.Evidence = []string{fmt.Sprintf("Set-Cookie: %s (no Secure)", cookie.Name), "URL: " + sourceURL}
		f.Confidence = "HIGH"
		f.Recommendation = "Add the Secure flag to all session and auth cookies."
		f.Tags = []string{"cookies", "iam"}
		findings = append(findings, f)
	}

	if !cookie.HttpOnly {
		sev := finding.Low
		if isAuth {
			sev = finding.Medium
		}
		f := finding.NewFinding(moduleName, hostName,
			fmt.Sprintf("Cookie %q missing HttpOnly flag", cookie.Name),
			fmt.Sprintf("Cookie %q is accessible via JavaScript. Any XSS on this domain allows "+
				"direct theft of this cookie.", cookie.Name),
			sev,
		)
		f.ID = "cookies-httponly"
		f.Evidence = []string{fmt.Sprintf("Set-Cookie: %s (no HttpOnly)", cookie.Name), "URL: " + sourceURL}
		f.Confidence = "HIGH"
		f.Recommendation = "Set HttpOnly on all session and authentication cookies."
		f.Tags = []string{"cookies", "iam"}
		findings = append(findings, f)
	}

	if cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure {
		f := finding.NewFinding(moduleName, hostName,
			fmt.Sprintf("Cookie %q has SameSite=None without Secure", cookie.Name),
			"SameSite=None requires the Secure flag. Without it the cookie is rejected by modern "+
				"browsers or transmitted over HTTP.",
			finding.High,
		)
		f.ID = "cookies-samesite-none"
		f.Evidence = []string{fmt.Sprintf("Set-Cookie: %s; SameSite=None (no Secure)", cookie.Name)}
		f.Confidence = "HIGH"
		f.Recommendation = "SameSite=None mandates the Secure flag. Prefer SameSite=Strict for auth cookies."
		f.Tags = []string{"cookies", "iam"}
		findings = append(findings, f)
	} else if cookie.SameSite == http.SameSiteDefaultMode {
		f := finding.NewFinding(moduleName, hostName,
			fmt.Sprintf("Cookie %q missing SameSite attribute", cookie.Name),
			fmt.Sprintf("No SameSite attribute on cookie %q. Explicit SameSite=Strict prevents CSRF "+
				"by blocking cross-site requests from including the cookie.", cookie.Name),
			finding.Low,
		)
		f.ID = "cookies-samesite"
		f.Evidence = []string{fmt.Sprintf("Set-Cookie: %s (no SameSite)", cookie.Name)}
		f.Confidence = "HIGH"
		f.Recommendation = "Set SameSite=Strict on session cookies."
		f.Tags = []string{"cookies", "iam"}
		findings = append(findings, f)
	}

	if !cookie.Expires.IsZero() && cookie.Expires.After(time.Now()) {
		remaining := time.Until(cookie.Expires)
		if isAuth && remaining > 24*time.Hour {
			f := finding.NewFinding(moduleName, hostName,
				fmt.Sprintf("Session cookie %q has long persistent expiry", cookie.Name),
				fmt.Sprintf("Session cookie %q expires in %.0f days. Persistent auth cookies extend "+
					"the window for session hijacking after a device is lost or stolen.",
					cookie.Name, remaining.Hours()/24),
				finding.Low,
			)
			f.ID = "cookies-persistent"
			f.Evidence = []string{
				fmt.Sprintf("Expires: %s", cookie.Expires.Format(time.RFC1123)),
				fmt.Sprintf("Remaining: %.0f days", remaining.Hours()/24),
			}
			f.Confidence = "HIGH"
			f.Recommendation = "Use session-scoped cookies (no Expires/Max-Age) for auth. If persistence is needed, limit to 8-24 hours."
			f.Tags = []string{"cookies", "iam"}
			findings = append(findings, f)
		}
	}

	if cookie.Domain != "" && strings.HasPrefix(cookie.Domain, ".") {
		parts := strings.Split(strings.TrimPrefix(cookie.Domain, "."), ".")
		if len(parts) <= 2 {
			f := finding.NewFinding(moduleName, hostName,
				fmt.Sprintf("Cookie %q scoped to overly broad domain %q", cookie.Name, cookie.Domain),
				fmt.Sprintf("Domain=%q covers all subdomains. A subdomain takeover or XSS on any "+
					"subdomain allows theft of this cookie.", cookie.Domain),
				finding.Medium,
			)
			f.ID = "cookies-broad-domain"
			f.Evidence = []string{fmt.Sprintf("Set-Cookie: %s; Domain=%s", cookie.Name, cookie.Domain)}
			f.Confidence = "MEDIUM"
			f.Recommendation = "Scope auth cookies to the specific hostname, not a wildcard domain."
			f.Tags = []string{"cookies", "iam"}
			findings = append(findings, f)
		}
	}

	if isAuth {
		f := finding.NewFinding(moduleName, hostName,
			fmt.Sprintf("Session/auth cookie detected: %q", cookie.Name),
			fmt.Sprintf("Cookie %q is an authentication or session cookie. All security flags should be verified.", cookie.Name),
			finding.Info,
		)
		f.Evidence = []string{"Cookie: " + cookie.Name, "URL: " + sourceURL}
		f.Confidence = "HIGH"
		f.Recommendation = "Verify Secure, HttpOnly, and SameSite=Strict are set on this cookie."
		f.Tags = []string{"cookies", "iam"}
		findings = append(findings, f)
	}

	return findings
}

// MultipleCookies returns a finding when more than two distinct auth cookie
// names are detected, indicating fragmented session architecture.
func MultipleCookies(hostName string, authCookieNames map[string]bool) finding.Finding {
	names := make([]string, 0, len(authCookieNames))
	for name := range authCookieNames {
		names = append(names, name)
	}
	f := finding.NewFinding(moduleName, hostName,
		"Multiple session/auth cookies detected",
		fmt.Sprintf("%d distinct session or auth cookies found: %s. Multiple session cookies indicate "+
			"fragmented session architecture, making consistent flag enforcement and proper logout difficult.",
			len(names), strings.Join(names, ", ")),
		finding.Low,
	)
	f.ID = "cookies-multiple"
	f.Evidence = names
	f.Confidence = "HIGH"
	f.Recommendation = "Consolidate to a single session cookie. Ensure logout invalidates all session tokens."
	f.Tags = []string{"cookies", "iam"}
	return f
}
