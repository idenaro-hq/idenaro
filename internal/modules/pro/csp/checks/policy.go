package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// ParseCSP splits a CSP header value into a map of directive → token slice.
func ParseCSP(csp string) map[string][]string {
	result := map[string][]string{}
	for _, part := range strings.Split(csp, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		directive := strings.ToLower(fields[0])
		result[directive] = fields[1:]
	}
	return result
}

// Policy performs deep analysis of a parsed CSP and returns all findings.
// url is the page URL the CSP was retrieved from (used in evidence).
func Policy(host, rawCSP, url string) []finding.Finding {
	d := ParseCSP(rawCSP)
	var findings []finding.Finding

	effectiveScriptSrc := getEffective(d, "script-src", "default-src")
	effectiveStyleSrc := getEffective(d, "style-src", "default-src")
	effectiveDefaultSrc := d["default-src"]

	if containsAny(effectiveScriptSrc, "'unsafe-inline'") {
		f := finding.NewFinding(moduleName, host,
			"CSP allows unsafe-inline scripts",
			"The script-src or default-src directive includes 'unsafe-inline', which allows inline "+
				"JavaScript execution. This completely negates XSS protection on this page. "+
				"Login pages are high-value XSS targets for credential harvesting.",
			finding.High,
		)
		f.ID = "csp-unsafe-inline"
		f.Evidence = []string{
			"script-src contains: 'unsafe-inline'",
			"CSP: " + truncate(rawCSP, 150),
			"URL: " + url,
		}
		f.Confidence = "HIGH"
		f.Recommendation = "Remove 'unsafe-inline'. Use nonces or hashes for legitimate inline scripts. " +
			"Refactor inline event handlers to external script files."
		f.Tags = []string{"csp", "headers", "iam"}
		findings = append(findings, f)
	}

	if containsAny(effectiveScriptSrc, "'unsafe-eval'") {
		f := finding.NewFinding(moduleName, host,
			"CSP allows unsafe-eval",
			"'unsafe-eval' permits dynamic JavaScript execution via eval(), Function(), setTimeout(string), "+
				"and similar. Attackers who can inject data into these calls achieve XSS despite CSP.",
			finding.Medium,
		)
		f.ID = "csp-unsafe-eval"
		f.Evidence = []string{"script-src contains: 'unsafe-eval'", "URL: " + url}
		f.Confidence = "HIGH"
		f.Recommendation = "Remove 'unsafe-eval'. Refactor code using eval() to avoid dynamic execution."
		f.Tags = []string{"csp", "headers", "iam"}
		findings = append(findings, f)
	}

	for _, src := range []string{"script-src", "default-src", "style-src", "frame-src", "connect-src"} {
		vals := getEffective(d, src, "default-src")
		if containsAny(vals, "*") {
			f := finding.NewFinding(moduleName, host,
				fmt.Sprintf("CSP %s uses wildcard source", src),
				fmt.Sprintf("The %s directive contains a wildcard (*), allowing resources from any origin. "+
					"This defeats the purpose of CSP for this resource type.", src),
				finding.Medium,
			)
			f.ID = "csp-wildcard-src"
			f.Evidence = []string{fmt.Sprintf("%s: *", src), "URL: " + url}
			f.Confidence = "HIGH"
			f.Recommendation = fmt.Sprintf("Replace * in %s with explicit trusted origins.", src)
			f.Tags = []string{"csp", "headers", "iam"}
			findings = append(findings, f)
		}
	}

	if _, ok := d["frame-ancestors"]; !ok {
		f := finding.NewFinding(moduleName, host,
			"CSP missing frame-ancestors directive",
			"The frame-ancestors directive is absent. This is the modern replacement for X-Frame-Options "+
				"and prevents login page embedding in iframes for clickjacking attacks. "+
				"frame-ancestors in CSP takes precedence over X-Frame-Options in modern browsers.",
			finding.Medium,
		)
		f.ID = "csp-frame-ancestors"
		f.Evidence = []string{"frame-ancestors not present in CSP", "URL: " + url}
		f.Confidence = "HIGH"
		f.Recommendation = "Add frame-ancestors 'none' or frame-ancestors 'self' to CSP."
		f.Tags = []string{"csp", "headers", "iam"}
		findings = append(findings, f)
	}

	if _, ok := d["form-action"]; !ok {
		f := finding.NewFinding(moduleName, host,
			"CSP missing form-action directive",
			"Without form-action, a form on this page can POST to any URL. "+
				"If an attacker can inject a form or modify form targets, credentials are sent to attacker infrastructure.",
			finding.Low,
		)
		f.ID = "csp-form-action"
		f.Evidence = []string{"form-action not present in CSP", "URL: " + url}
		f.Confidence = "MEDIUM"
		f.Recommendation = "Add form-action 'self' to restrict where forms can submit data."
		f.Tags = []string{"csp", "headers", "iam"}
		findings = append(findings, f)
	}

	if _, ok := d["base-uri"]; !ok {
		f := finding.NewFinding(moduleName, host,
			"CSP missing base-uri directive",
			"Without base-uri, an attacker who can inject a <base> tag can redirect all relative URLs "+
				"(including script sources and form actions) to an attacker-controlled origin.",
			finding.Low,
		)
		f.ID = "csp-base-uri"
		f.Evidence = []string{"base-uri not present in CSP", "URL: " + url}
		f.Confidence = "MEDIUM"
		f.Recommendation = "Add base-uri 'self' or base-uri 'none' to prevent base tag injection."
		f.Tags = []string{"csp", "headers", "iam"}
		findings = append(findings, f)
	}

	if len(effectiveDefaultSrc) == 0 {
		f := finding.NewFinding(moduleName, host,
			"CSP has no default-src fallback",
			"The CSP has no default-src directive. Directives not explicitly set fall back to allowing "+
				"everything. This creates coverage gaps for resource types not individually listed.",
			finding.Medium,
		)
		f.ID = "csp-no-default"
		f.Evidence = []string{"default-src absent from CSP", "CSP: " + truncate(rawCSP, 150)}
		f.Confidence = "HIGH"
		f.Recommendation = "Add default-src 'none' or default-src 'self' as a safe fallback."
		f.Tags = []string{"csp", "headers", "iam"}
		findings = append(findings, f)
	}

	if containsAny(effectiveStyleSrc, "'unsafe-inline'") {
		f := finding.NewFinding(moduleName, host,
			"CSP allows unsafe-inline styles",
			"'unsafe-inline' in style-src allows injected CSS. While lower severity than script injection, "+
				"CSS injection enables UI redressing attacks on login forms to steal credentials.",
			finding.Low,
		)
		f.Evidence = []string{"style-src contains: 'unsafe-inline'", "URL: " + url}
		f.Confidence = "HIGH"
		f.Recommendation = "Remove 'unsafe-inline' from style-src. Use nonces or hashes for legitimate inline styles."
		f.Tags = []string{"csp", "headers", "iam"}
		findings = append(findings, f)
	}

	return findings
}
