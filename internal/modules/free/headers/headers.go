package headers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"idenaro/internal/finding"
	"idenaro/internal/modules"
	"idenaro/pkg/httpclient"
)

const moduleName = "headers"

// headerRule describes a single HTTP response header security check.
type headerRule struct {
	HeaderName  string
	Severity    finding.Severity
	Title       string
	Description string
	Recommend   string
	DocID       string
	// validate returns (passed, evidence). Only called when the header is present.
	validate func(headerValue string) (passed bool, evidence string)
}

// securityHeaderRules covers every header the module checks for presence and
// correct configuration. Add new rules here; the Run loop handles them automatically.
var securityHeaderRules = []headerRule{
	{
		HeaderName: "Strict-Transport-Security",
		Severity:   finding.High,
		DocID:      "headers-hsts",
		Title:      "Missing Strict-Transport-Security (HSTS) header",
		Description: "HSTS forces browsers to use HTTPS exclusively. Without it, users are vulnerable " +
			"to SSL stripping attacks where attackers downgrade HTTPS connections to HTTP.",
		Recommend: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
		validate: func(headerValue string) (bool, string) {
			if !strings.Contains(headerValue, "max-age") {
				return false, fmt.Sprintf("HSTS header present but missing max-age directive: %q", headerValue)
			}
			return true, ""
		},
	},
	{
		HeaderName: "Content-Security-Policy",
		Severity:   finding.Medium,
		DocID:      "headers-csp",
		Title:      "Missing Content-Security-Policy (CSP) header",
		Description: "CSP prevents cross-site scripting and data injection attacks by specifying " +
			"which content sources are trusted. Without it, injected scripts run unchecked.",
		Recommend: "Start with: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
		validate: func(headerValue string) (bool, string) {
			// Parse into directives so we check the specific directive that
			// contains unsafe-inline, not just a substring of the full header.
			dirs := parseCSPDirectives(headerValue)
			// script-src falls back to default-src when absent.
			scriptSrc, ok := dirs["script-src"]
			if !ok {
				scriptSrc = dirs["default-src"]
			}
			for _, tok := range scriptSrc {
				if strings.EqualFold(tok, "'unsafe-inline'") {
					return false, fmt.Sprintf("script-src contains 'unsafe-inline': %q", headerValue)
				}
			}
			return true, ""
		},
	},
	{
		HeaderName: "X-Frame-Options",
		Severity:   finding.Medium,
		DocID:      "headers-xframe",
		Title:      "Missing X-Frame-Options header",
		Description: "Without frame protection, login pages can be embedded in attacker-controlled " +
			"iframes, enabling clickjacking attacks to capture credentials.",
		Recommend: "Add: X-Frame-Options: DENY",
		validate:  func(_ string) (bool, string) { return true, "" },
	},
	{
		HeaderName: "X-Content-Type-Options",
		Severity:   finding.Low,
		DocID:      "headers-xcto",
		Title:      "Missing X-Content-Type-Options header",
		Description: "Without nosniff, browsers may MIME-sniff responses away from their declared " +
			"content type, enabling scenarios where uploaded files are executed as scripts.",
		Recommend: "Add: X-Content-Type-Options: nosniff",
		validate:  func(_ string) (bool, string) { return true, "" },
	},
	{
		HeaderName: "Referrer-Policy",
		Severity:   finding.Low,
		DocID:      "headers-referrer",
		Title:      "Missing Referrer-Policy header",
		Description: "Without a referrer policy, authentication tokens or session IDs present in URLs " +
			"may leak to third-party resources via the Referer header.",
		Recommend: "Add: Referrer-Policy: strict-origin-when-cross-origin",
		validate:  func(_ string) (bool, string) { return true, "" },
	},
	{
		HeaderName: "Permissions-Policy",
		Severity:   finding.Info,
		DocID:      "headers-permissions",
		Title:      "Missing Permissions-Policy header",
		Description: "Permissions-Policy restricts browser feature access (camera, microphone, geolocation). " +
			"Relevant for identity portals to reduce attack surface.",
		Recommend: "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
		validate:  func(_ string) (bool, string) { return true, "" },
	},
}

// infoLeakHeaders maps header names to a short description of what they disclose.
// Their presence triggers a LOW severity information-disclosure finding.
var infoLeakHeaders = map[string]string{
	"Server":           "Exposes web server software and version",
	"X-Powered-By":     "Exposes backend technology stack",
	"X-AspNet-Version": "Exposes ASP.NET framework version",
	"X-Generator":      "Exposes CMS or framework identity",
}

// parseCSPDirectives splits a Content-Security-Policy header value into a map
// of lowercase directive name → token slice. Used by the CSP validator to
// check specific directives rather than doing raw substring matching.
func parseCSPDirectives(csp string) map[string][]string {
	result := make(map[string][]string)
	for _, part := range strings.Split(csp, ";") {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) == 0 {
			continue
		}
		result[strings.ToLower(fields[0])] = fields[1:]
	}
	return result
}

// Scanner implements the security headers check module.
type Scanner struct {
	httpClient *http.Client
}

func New(opts httpclient.Options) modules.Module {
	return &Scanner{httpClient: httpclient.New(opts)}
}

func (s *Scanner) Name() string { return moduleName }

func (s *Scanner) Run(ctx context.Context, target modules.Target) ([]finding.Finding, error) {
	var findings []finding.Finding

	rootURL := target.BaseURL() + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rootURL, nil)
	if err != nil {
		return nil, fmt.Errorf("headers: failed to build request for %s: %w", rootURL, err)
	}
	req.Header.Set("User-Agent", httpclient.DefaultUserAgent)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, nil // host unreachable - not an error condition
	}
	defer resp.Body.Close()

	for _, rule := range securityHeaderRules {
		headerValue := resp.Header.Get(rule.HeaderName)

		if headerValue == "" {
			missingHeaderFinding := finding.NewFinding(moduleName, target.Host,
				rule.Title, rule.Description, rule.Severity)
			if rule.DocID != "" {
				missingHeaderFinding.ID = rule.DocID
			}
			missingHeaderFinding.Evidence = []string{
				fmt.Sprintf("Header %q absent from response at %s", rule.HeaderName, rootURL),
				fmt.Sprintf("HTTP %d response", resp.StatusCode),
			}
			missingHeaderFinding.Confidence = "HIGH"
			missingHeaderFinding.Recommendation = rule.Recommend
			missingHeaderFinding.Tags = []string{"headers", "iam"}
			findings = append(findings, missingHeaderFinding)
			continue
		}

		if rule.validate != nil {
			if passed, validationEvidence := rule.validate(headerValue); !passed {
				misconfiguredTitle := strings.Replace(rule.Title, "Missing ", "Misconfigured ", 1)
				misconfiguredFinding := finding.NewFinding(moduleName, target.Host,
					misconfiguredTitle, rule.Description, rule.Severity)
				if rule.DocID != "" {
					misconfiguredFinding.ID = rule.DocID
				}
				misconfiguredFinding.Evidence = []string{validationEvidence, fmt.Sprintf("URL: %s", rootURL)}
				misconfiguredFinding.Confidence = "HIGH"
				misconfiguredFinding.Recommendation = rule.Recommend
				misconfiguredFinding.Tags = []string{"headers", "iam"}
				findings = append(findings, misconfiguredFinding)
			} else {
				okTitle := strings.Replace(rule.Title, "Missing ", "", 1) + " correctly configured"
				okFinding := finding.NewFinding(moduleName, target.Host,
					okTitle,
					fmt.Sprintf("The %s header is present and correctly configured.", rule.HeaderName),
					finding.Info,
				)
				if rule.DocID != "" {
					okFinding.ID = rule.DocID + "-ok"
				}
				okFinding.Evidence = []string{fmt.Sprintf("%s: %s", rule.HeaderName, headerValue)}
				okFinding.Confidence = "HIGH"
				okFinding.Recommendation = "No action required."
				okFinding.Tags = []string{"headers", "iam"}
				findings = append(findings, okFinding)
			}
		}
	}

	for headerName, disclosure := range infoLeakHeaders {
		if headerValue := resp.Header.Get(headerName); headerValue != "" {
			infoLeakFinding := finding.NewFinding(moduleName, target.Host,
				fmt.Sprintf("Information disclosure via %q header", headerName),
				disclosure+". This aids attacker reconnaissance by revealing which software versions to target.",
				finding.Low,
			)
			infoLeakFinding.ID = "headers-info-disclosure"
			infoLeakFinding.Evidence = []string{fmt.Sprintf("%s: %s", headerName, headerValue)}
			infoLeakFinding.Confidence = "HIGH"
			infoLeakFinding.Recommendation = fmt.Sprintf(
				"Remove or suppress the %q header in your web server configuration.", headerName)
			infoLeakFinding.Tags = []string{"headers", "iam"}
			findings = append(findings, infoLeakFinding)
		}
	}

	return findings, nil
}
