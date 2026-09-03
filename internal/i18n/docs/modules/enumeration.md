## enumeration-overview | Enumeration | 

The Enumeration module tests authentication flow endpoints for response differences that reveal whether a submitted username or email address is registered. User enumeration enables account targeting in credential stuffing, brute-force, and social engineering attacks.

### Checks performed

- Password reset form: different response wording for valid vs. invalid addresses
- Login error messages: distinct messages for "user not found" vs. "wrong password"
- Account status disclosure: locked, suspended, or disabled account indicated in login flow
- User data API endpoints accessible without authentication

---

## enum-reset-wording | User Enumeration via Password Reset Wording | MEDIUM

The password reset page returns different messages for existing and non-existing accounts ("user not found", "email not found", "no account with that email"). Attackers can use this to build a list of valid accounts for targeted credential attacks.

### Remediation

- Return an identical response for all reset requests: "If an account with that email exists, you will receive a reset link."
- Ensure response times are consistent (use constant-time operations).
- Implement rate limiting on the reset endpoint.

---

## enum-login-wording | User Enumeration via Login Error Message | MEDIUM

The login page distinguishes between "user not found" and "wrong password" errors, allowing attackers to determine which usernames are valid before attempting password-based attacks.

### Remediation

- Return a generic error for all authentication failures: "Invalid credentials."
- Never distinguish between unknown username and wrong password in error messages.
- Ensure response times are consistent regardless of whether the user exists.

---

## enum-account-status | Account Status Revealed in Login Flow | MEDIUM

The login flow reveals specific account states ("account locked", "account disabled", "account suspended"). While this confirms the account exists, it also reveals security-relevant account state to unauthenticated users.

### Remediation

- Return generic error messages that do not reveal account state to unauthenticated users.
- Communicate account-specific issues via the registered email address instead.

---

## enum-user-api | User Data Accessible Without Authentication | HIGH

A user listing or search API endpoint returned JSON user records (email, username, displayName) without requiring authentication. This enables mass enumeration of all user accounts in the system.

### Remediation

- Require authentication for all user management and listing endpoints.
- Apply principle of least privilege: regular users should not be able to enumerate all accounts.
- Implement pagination and rate limiting on user search endpoints.
