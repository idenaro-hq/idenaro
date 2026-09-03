package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// MFADetection carries the MFA presence and strength state detected on a login page.
type MFADetection struct {
	Found         bool
	StrengthLevel int
	StrengthLabel string
	StepUpFound   bool
}

// LoginPage scans the login page body for MFA weakness patterns and updates
// detection state. Returns weakness findings and the updated detection.
func LoginPage(host, pageURL, bodyStr string) ([]finding.Finding, MFADetection) {
	var findings []finding.Finding
	var det MFADetection

	lower := strings.ToLower(bodyStr)

	for _, ind := range mfaStrengthIndicators {
		for _, kw := range ind.keywords {
			if strings.Contains(lower, kw) {
				det.Found = true
				if ind.strength > det.StrengthLevel {
					det.StrengthLevel = ind.strength
					det.StrengthLabel = ind.label
				}
				break
			}
		}
	}

	for _, wp := range weaknessPhrases {
		if strings.Contains(lower, wp.phrase) {
			f := finding.NewFinding(moduleName, host,
				wp.title,
				fmt.Sprintf("The login page at %s contains %q, indicating a potential MFA bypass or weakening mechanism.",
					pageURL, wp.phrase),
				wp.severity,
			)
			if wp.docID != "" {
				f.ID = wp.docID
			}
			f.Evidence = []string{fmt.Sprintf("Pattern %q found at: %s", wp.phrase, pageURL)}
			f.Confidence = "LOW"
			f.Recommendation = "MFA bypass and skip mechanisms undermine the security guarantee of MFA. " +
				"Remove remember-device options or restrict them to verified managed devices only."
			f.Tags = []string{"mfa", "iam"}
			findings = append(findings, f)
		}
	}

	for _, ind := range stepUpIndicators {
		if strings.Contains(lower, ind) {
			det.StepUpFound = true
			break
		}
	}

	return findings, det
}

// Synthesize produces findings about MFA presence, absence, or strength based on
// the combined detection state from login page analysis and API probe results.
func Synthesize(host, loginURL string, det MFADetection) []finding.Finding {
	var findings []finding.Finding

	if !det.Found {
		f := finding.NewFinding(moduleName, host,
			"No MFA indicators detected on login endpoint",
			fmt.Sprintf("Comprehensive analysis of the login page at %s found no evidence of multi-factor authentication. "+
				"No MFA-related headers, HTML indicators, or known MFA API endpoints were detected. "+
				"NIS2 Art. 21 (2)(i) mandates MFA for access to critical systems.", loginURL),
			finding.Medium,
		)
		f.ID = "mfa-missing"
		f.Evidence = []string{
			fmt.Sprintf("Login page: %s", loginURL),
			"No MFA headers detected",
			"No MFA HTML indicators (totp, 2fa, otp, authenticator, webauthn, fido, passkey)",
			"No MFA API endpoints responded to HEAD probe",
		}
		f.Confidence = "LOW"
		f.Recommendation = "Implement MFA for all user accounts. Prefer WebAuthn/FIDO2 or TOTP. " +
			"Enforce MFA for all authentication flows, not just admin accounts."
		f.Tags = []string{"mfa", "iam"}
		findings = append(findings, f)
		return findings
	}

	switch det.StrengthLevel {
	case 1:
		f := finding.NewFinding(moduleName, host,
			fmt.Sprintf("Weak MFA method detected: %s", det.StrengthLabel),
			fmt.Sprintf("The login page indicates %s is in use. This is a weak MFA factor: "+
				"SMS OTP is vulnerable to SIM swapping, number porting, and SS7 attacks. "+
				"Email OTP is vulnerable to email account compromise.", det.StrengthLabel),
			finding.Medium,
		)
		f.ID = "mfa-weak"
		f.Evidence = []string{fmt.Sprintf("MFA indicator: %s at %s", det.StrengthLabel, loginURL)}
		f.Confidence = "LOW"
		f.Recommendation = "Upgrade to TOTP authenticator apps or WebAuthn/FIDO2. " +
			"Use SMS/email OTP only as a fallback, not a primary factor."
		f.Tags = []string{"mfa", "iam"}
		findings = append(findings, f)
	case 2:
		f := finding.NewFinding(moduleName, host,
			fmt.Sprintf("MFA present: %s", det.StrengthLabel),
			fmt.Sprintf("The login page indicates %s is in use. This is a medium-strength MFA factor.", det.StrengthLabel),
			finding.Info,
		)
		f.Evidence = []string{fmt.Sprintf("MFA indicator: %s", det.StrengthLabel)}
		f.Confidence = "LOW"
		f.Recommendation = "Consider offering WebAuthn/FIDO2 as a stronger option alongside TOTP."
		f.Tags = []string{"mfa", "iam"}
		findings = append(findings, f)
	case 3:
		f := finding.NewFinding(moduleName, host,
			fmt.Sprintf("Strong MFA detected: %s", det.StrengthLabel),
			fmt.Sprintf("The login page indicates %s is supported. This is the strongest available MFA factor.", det.StrengthLabel),
			finding.Info,
		)
		f.Evidence = []string{fmt.Sprintf("MFA indicator: %s", det.StrengthLabel)}
		f.Confidence = "LOW"
		f.Recommendation = "Ensure phishing-resistant MFA is enforced for all users, not just available."
		f.Tags = []string{"mfa", "iam"}
		findings = append(findings, f)
	}

	if det.StepUpFound {
		f := finding.NewFinding(moduleName, host,
			"Step-up authentication indicators detected",
			"The login flow shows indicators of step-up authentication - additional verification "+
				"for sensitive actions. This is a positive security control.",
			finding.Info,
		)
		f.Evidence = []string{fmt.Sprintf("Step-up indicator found at: %s", loginURL)}
		f.Confidence = "LOW"
		f.Recommendation = "Ensure step-up auth is enforced for all privilege-escalating actions: " +
			"password changes, MFA management, admin access, and payment operations."
		f.Tags = []string{"mfa", "iam"}
		findings = append(findings, f)
	}

	return findings
}
