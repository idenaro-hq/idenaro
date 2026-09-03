package checks

// MFAEndpointPaths are the paths probed via HEAD to corroborate MFA API presence.
var MFAEndpointPaths = []string{
	"/api/auth/mfa", "/api/mfa", "/verify-otp", "/auth/mfa",
	"/auth/2fa", "/login/mfa", "/login/2fa", "/totp/verify",
}
