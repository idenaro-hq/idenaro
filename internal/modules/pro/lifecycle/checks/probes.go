package checks

import "idenaro/internal/finding"

// Probe defines an account lifecycle endpoint to check.
type Probe struct {
	Path        string
	Name        string
	Description string
	Severity    finding.Severity
	Tags        []string
	Recommend   string
}

// Probes is the ordered list of lifecycle endpoints to probe.
var Probes = []Probe{
	// ── Registration ──────────────────────────────────────────────────────────
	{"/register", "self-service registration",
		"A self-service registration endpoint is publicly accessible. " +
			"Verify registration requires email verification, CAPTCHA, and does not allow privileged account creation.",
		finding.Info, []string{"lifecycle", "iam", "enumeration"},
		"Ensure registration requires email verification. Implement rate limiting and CAPTCHA. " +
			"Never allow role/permission assignment during self-registration."},
	{"/signup", "self-service signup",
		"A signup page is publicly accessible.",
		finding.Info, []string{"lifecycle", "iam"},
		"Verify signup includes email verification and rate limiting."},
	{"/auth/register", "auth register endpoint",
		"An authentication registration endpoint is accessible.",
		finding.Info, []string{"lifecycle", "iam"},
		"Ensure registration requires email verification and does not allow privilege assignment."},
	{"/api/v1/register", "API registration endpoint",
		"An API registration endpoint is publicly accessible. Verify it cannot be abused for mass account creation.",
		finding.Medium, []string{"lifecycle", "iam", "admin-exposure"},
		"Rate limit registration APIs. Require CAPTCHA or invite token for registration."},

	// ── Invitation flows ──────────────────────────────────────────────────────
	{"/invite", "invitation endpoint",
		"An invitation management endpoint is accessible. " +
			"If unauthenticated, attackers may be able to send invitations or enumerate invited users.",
		finding.Medium, []string{"lifecycle", "iam", "admin-exposure"},
		"Restrict invitation management to authenticated administrators only."},
	{"/api/invitations", "invitations API",
		"An invitations API is publicly accessible.",
		finding.Medium, []string{"lifecycle", "iam", "admin-exposure"},
		"Require admin authentication for all invitation management endpoints."},
	{"/admin/invite", "admin invitation endpoint",
		"An admin invitation endpoint is accessible.",
		finding.High, []string{"lifecycle", "iam", "admin-exposure"},
		"Admin invitation endpoints must require authenticated admin sessions."},

	// ── Account activation / verification ─────────────────────────────────────
	{"/activate", "account activation endpoint",
		"An account activation endpoint is accessible. " +
			"Verify activation tokens are single-use, time-limited, and cryptographically random.",
		finding.Low, []string{"lifecycle", "iam"},
		"Use cryptographically random activation tokens. Set expiry of 24-48 hours. " +
			"Invalidate tokens after first use."},
	{"/verify", "account verification endpoint",
		"An account verification endpoint is accessible.",
		finding.Low, []string{"lifecycle", "iam"},
		"Ensure verification tokens are time-limited and single-use."},
	{"/confirm", "account confirmation endpoint",
		"An account confirmation endpoint is accessible.",
		finding.Low, []string{"lifecycle", "iam"},
		"Use time-limited, single-use confirmation tokens."},
	{"/email/verify", "email verification endpoint",
		"An email verification endpoint is accessible.",
		finding.Low, []string{"lifecycle", "iam"},
		"Implement rate limiting on email verification to prevent token brute force."},

	// ── Account unlock / recovery ─────────────────────────────────────────────
	{"/unlock", "account unlock endpoint",
		"An account unlock endpoint is publicly accessible. " +
			"If not properly controlled, this could allow bypassing account lockout policies.",
		finding.Medium, []string{"lifecycle", "iam"},
		"Require strong authentication for account unlock. Log all unlock events."},
	{"/account/unlock", "account unlock endpoint",
		"An account unlock endpoint is accessible.",
		finding.Medium, []string{"lifecycle", "iam"},
		"Require admin approval or strong identity verification before unlocking accounts."},
	{"/unblock", "account unblock endpoint",
		"An account unblock endpoint is accessible.",
		finding.Medium, []string{"lifecycle", "iam"},
		"Require authentication and authorization checks before unblocking accounts."},

	// ── Account disable / offboarding ─────────────────────────────────────────
	{"/admin/users/disable", "user disable endpoint",
		"An admin user-disable endpoint is publicly accessible.",
		finding.High, []string{"lifecycle", "iam", "admin-exposure"},
		"Restrict account disable operations to authenticated administrators."},
	{"/api/v1/users/disable", "API user disable",
		"A user disable API endpoint is accessible.",
		finding.High, []string{"lifecycle", "iam", "admin-exposure"},
		"Require admin authentication for all user management API endpoints."},

	// ── Impersonation ─────────────────────────────────────────────────────────
	{"/admin/impersonate", "admin impersonation endpoint",
		"An admin user impersonation endpoint is accessible. " +
			"Impersonation endpoints allow admins to act as other users - high-risk if exposed without authentication.",
		finding.Critical, []string{"lifecycle", "iam", "admin-exposure"},
		"Restrict impersonation to authenticated super-admins. Log all impersonation events with full audit trail. " +
			"Require MFA re-authentication before impersonation."},
	{"/api/impersonate", "API impersonation endpoint",
		"An impersonation API endpoint is accessible.",
		finding.Critical, []string{"lifecycle", "iam", "admin-exposure"},
		"Impersonation must require admin authentication and generate an auditable event."},
	{"/auth/impersonate", "auth impersonation endpoint",
		"An auth impersonation endpoint is accessible.",
		finding.Critical, []string{"lifecycle", "iam", "admin-exposure"},
		"Restrict impersonation strictly. Require fresh MFA authentication before use."},
	{"/realms/master/users", "Keycloak user management (master realm)",
		"The Keycloak master realm user management endpoint is accessible. " +
			"This provides full control over all users across all realms.",
		finding.Critical, []string{"lifecycle", "iam", "admin-exposure"},
		"The Keycloak master realm admin API must never be publicly accessible. Restrict to admin networks."},

	// ── SCIM provisioning (lifecycle-relevant paths) ──────────────────────────
	{"/scim/v2/Users", "SCIM user provisioning",
		"A SCIM user provisioning endpoint is accessible. SCIM provides full CRUD over user accounts.",
		finding.High, []string{"lifecycle", "iam", "scim", "admin-exposure"},
		"SCIM endpoints require Bearer token authentication. Restrict to your provisioning system's IP range."},

	// ── Bulk operations ───────────────────────────────────────────────────────
	{"/admin/users/import", "bulk user import endpoint",
		"A bulk user import endpoint is accessible. " +
			"If unauthenticated, this could allow mass account creation or privilege escalation.",
		finding.High, []string{"lifecycle", "iam", "admin-exposure"},
		"Restrict bulk import to authenticated administrators. Validate all imported data."},
	{"/api/v1/users/bulk", "bulk user API",
		"A bulk user management API endpoint is accessible.",
		finding.High, []string{"lifecycle", "iam", "admin-exposure"},
		"Require admin authentication for all bulk user management operations."},

	// ── Password management ───────────────────────────────────────────────────
	{"/change-password", "password change endpoint",
		"A password change page is accessible. " +
			"Verify it requires current password before allowing the change (prevents CSRF-based password change).",
		finding.Info, []string{"lifecycle", "iam"},
		"Require current password verification. Use CSRF tokens. Consider requiring MFA for password changes."},
	{"/password/change", "password change endpoint",
		"A password change endpoint is accessible.",
		finding.Info, []string{"lifecycle", "iam"},
		"Require current password and a CSRF token for all password changes."},
	{"/api/v1/me/password", "API password change endpoint",
		"An API password change endpoint is accessible.",
		finding.Info, []string{"lifecycle", "iam"},
		"Require current password and re-authentication for password changes via API."},
}
