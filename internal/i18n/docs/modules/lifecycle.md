## lifecycle-overview | Account Lifecycle | 

The Account Lifecycle module probes user account management endpoints for unauthenticated access. These endpoints control user creation, privilege assignment, and session management - exposure can lead to account takeover, unauthorized registration, or privilege escalation without any credentials.

### Checks performed

- Impersonation endpoint accessible without authentication
- Open user self-registration endpoint
- Admin user invitation endpoint accessible
- Account unlock endpoint accessible without authentication
- Password change endpoint accessible without prior authentication (informational)

---

## lifecycle-impersonate | Impersonation Endpoint Accessible | CRITICAL

An admin impersonation endpoint is publicly accessible. Impersonation allows administrators to act as other users. If accessible without strong authentication, any attacker who can reach the endpoint can escalate to any user account in the system.

### Remediation

- Require step-up MFA re-authentication before any impersonation session begins.
- Restrict impersonation to named super-admin accounts only.
- Log every impersonation event with full audit trail and alert via email/SIEM.
- Auto-terminate impersonation sessions after 15 minutes.

---

## lifecycle-register-open | Open User Registration | MEDIUM

User registration is publicly accessible without invitation or approval. Open registration allows attackers to create accounts and access internal APIs, test features for vulnerabilities, and in some configurations escalate to higher privilege levels through self-service role selection.

### Remediation

- Require email domain verification or invitation-based registration.
- Confirm registration requires email verification.
- Implement CAPTCHA and rate limiting on registration.
- Ensure new accounts cannot self-assign roles or permissions during registration.

---

## lifecycle-invite | Admin Invitation Endpoint Accessible | HIGH

An administrative invitation management endpoint is accessible. If unauthenticated access is permitted, attackers can send invitations to arbitrary email addresses or enumerate invited users.

### Remediation

- Restrict invitation management to authenticated administrators only.
- Log all invitations sent and alert on unusual volumes.

---

## lifecycle-unlock | Account Unlock Endpoint Accessible | MEDIUM

An account unlock endpoint is publicly accessible. If not properly controlled, this can allow bypassing account lockout policies - a security control designed to slow brute-force attacks.

### Remediation

- Require strong identity verification before unlocking accounts.
- Send unlock confirmation to the user's registered email.
- Log and alert on all account unlock operations.

---

## lifecycle-password-change | Password Change Endpoint Accessible | INFO

A password change endpoint is accessible. Verify that it requires the current password before allowing the change (preventing CSRF-based password changes) and uses CSRF tokens on form submissions.

### What to verify

- Require current password verification before accepting a new password.
- Use CSRF tokens on the password change form.
- Consider requiring MFA re-authentication for password changes.
