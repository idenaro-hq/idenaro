## mfa-overview | MFA | 

The MFA module analyzes authentication pages and flows for multi-factor authentication coverage. It inspects visible UI elements, JavaScript, and endpoint responses for MFA indicators, weak method patterns, bypass opportunities, and enrollment surface exposure.

### Checks performed

- Presence of MFA indicators on login and challenge pages
- Weak MFA method detection: SMS OTP, email OTP
- MFA bypass patterns in page structure or response flows
- MFA disable option exposed on login or settings pages
- Backup and recovery code visibility during login
- Unauthenticated MFA bypass endpoint access
- OTP submission rate limiting
- MFA enrollment endpoint access without prior authentication

---

## mfa-missing | No MFA Indicators Detected | MEDIUM

No evidence of multi-factor authentication was found via analysis of the login page. NIS2 Art. 21(2)(i) requires MFA for access to critical systems. This is a heuristic check - manual confirmation is recommended.

### Remediation

- Enable MFA for all user accounts at the IdP level, not just administrator accounts.
- Enforce MFA in the IdP so it cannot be bypassed per-application.
- Prefer WebAuthn/FIDO2 over TOTP over Push MFA over SMS OTP.

---

## mfa-weak | Weak MFA Method Detected (SMS/Email OTP) | MEDIUM

SMS OTP is vulnerable to SIM swapping, number porting, and SS7 network attacks. Email OTP is vulnerable to email account compromise. Both are substantially weaker than TOTP or WebAuthn and should not be used as the primary second factor for privileged accounts.

### Remediation

- Offer TOTP authenticator apps as the default second factor.
- Deploy WebAuthn/FIDO2 security keys for administrators and privileged users.
- Use SMS/email only as a fallback with appropriate risk controls.

---

## mfa-bypass-pattern | MFA Bypass Pattern Detected | MEDIUM

The login page contains patterns indicating MFA can be bypassed or suppressed - "remember this device", "skip for 30 days", "don't ask again", or similar options. These create persistent MFA exemptions that extend the attack window after device theft or session hijacking.

### Remediation

- Disable remember-device options for administrative and privileged access.
- If required for UX: limit trust duration to 8 hours maximum.
- Bind device trust to device certificates, not browser cookies.

---

## mfa-disable-option | MFA Disable Option Present on Login Page | HIGH

The login page contains an option to disable MFA. An attacker with access to the account (via phishing or credential stuffing) can disable MFA before the legitimate user notices, permanently removing the second factor.

### Remediation

- Require step-up re-authentication before MFA can be disabled.
- Send notifications to the user's registered email when MFA is disabled.
- Implement a mandatory waiting period and confirmation link for MFA removal.

---

## mfa-backup-codes | Backup/Recovery Codes Exposed in Login Flow | LOW

The login page exposes backup or recovery code options prominently. Backup codes are static, long-lived credentials that bypass MFA entirely. Their prominence in the login flow increases awareness for attackers.

### Remediation

- Move backup code options behind an additional step, not on the primary login page.
- Limit backup codes to one-time use and generate them only on request.
- Log and alert on backup code usage.

---

## mfa-bypass-endpoint | MFA Bypass Endpoint Accessible | HIGH

An endpoint associated with MFA bypass, skip, or disable responded with HTTP 200. This warrants immediate investigation - MFA must not be bypassable via URL parameters or undocumented endpoints.

### Remediation

- Remove or disable the endpoint if it is not intentional.
- Require admin authentication and step-up MFA for any legitimate MFA management endpoint.
- Audit access logs for unauthorized attempts.

---

## mfa-otp-no-ratelimit | OTP Rate Limiting Absent | MEDIUM

No rate limiting or lockout was detected on the OTP verification endpoint. Without rate limiting, an attacker can brute-force 6-digit TOTP codes (1,000,000 possibilities) or SMS OTPs within the validity window.

### Remediation

- Implement lockout after 5 failed OTP attempts.
- Add exponential backoff between attempts.
- Alert on repeated OTP failures from the same IP or account.

---

## mfa-enrollment-open | MFA Enrollment Endpoint Accessible Without Authentication | MEDIUM

An MFA enrollment endpoint is accessible without requiring prior authentication. An attacker who accesses this endpoint first can register their own MFA device for a target account, locking out the legitimate user.

### Remediation

- Require authentication before MFA enrollment is permitted.
- Send confirmation to the user's registered contact when MFA is enrolled.
- Implement admin approval for MFA enrollment on privileged accounts.
