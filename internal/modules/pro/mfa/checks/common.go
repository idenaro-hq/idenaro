package checks

import "idenaro/internal/finding"

const moduleName = "mfa"

type mfaStrengthIndicator struct {
	keywords []string
	label    string
	strength int // 3=strong, 2=medium, 1=weak
}

var mfaStrengthIndicators = []mfaStrengthIndicator{
	{[]string{"webauthn", "fido2", "fido", "passkey", "security key"}, "WebAuthn/FIDO2", 3},
	{[]string{"authenticator app", "totp", "time-based", "google authenticator", "authy"}, "TOTP authenticator app", 2},
	{[]string{"push notification", "duo", "okta verify"}, "Push MFA", 2},
	{[]string{"sms", "text message", "phone number", "mobile number"}, "SMS OTP", 1},
	{[]string{"email otp", "email code", "email verification code"}, "Email OTP", 1},
}

type weaknessPhrase struct {
	phrase   string
	title    string
	severity finding.Severity
	docID    string
}

var weaknessPhrases = []weaknessPhrase{
	{"backup code", "Backup codes exposed in login flow", finding.Low, "mfa-backup-codes"},
	{"recovery code", "Recovery codes exposed in login flow", finding.Low, "mfa-backup-codes"},
	{"remember this device", "Remember-device option present (MFA bypass)", finding.Medium, "mfa-bypass-pattern"},
	{"remember this computer", "Remember-computer option present (MFA bypass)", finding.Medium, "mfa-bypass-pattern"},
	{"trust this device", "Trust-device option present (MFA bypass)", finding.Medium, "mfa-bypass-pattern"},
	{"skip for", "MFA skip option present", finding.Medium, "mfa-bypass-pattern"},
	{"skip mfa", "MFA skip option present", finding.Medium, "mfa-bypass-pattern"},
	{"don't ask again", "MFA suppression option present", finding.Medium, "mfa-bypass-pattern"},
	{"disable two-factor", "MFA disable option present on login page", finding.High, "mfa-disable-option"},
	{"disable 2fa", "MFA disable option present on login page", finding.High, "mfa-disable-option"},
	{"turn off two-factor", "MFA disable option present on login page", finding.High, "mfa-disable-option"},
}

var stepUpIndicators = []string{
	"re-enter your password", "confirm your identity", "verify it's you",
	"additional verification", "step-up", "re-authenticate",
	"confirm password", "enter your password to continue",
}
