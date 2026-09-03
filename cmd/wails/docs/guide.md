# Idenaro - User Guide

Idenaro is a IAM misconfiguration scanner. It analyzes Identity and Access Management endpoints to identify security weaknesses without requiring credentials or modifying target systems. All checks are read-only: no authentication is attempted, no data is written.

## Performing a Scan

### Adding Targets

Enter one or more hostnames in the **Targets** field. Press **Enter** or **Space** after each one. Supported formats:

- `auth.example.com`
- `auth.example.com:8443`
- `https://auth.example.com`

Remove a target by clicking its chip in the input area.

### Quick Presets

Presets activate a curated module selection for common scenarios:

- **Full scan** - All modules. Most comprehensive, takes the longest.
- **OIDC / OAuth2** - Discovery, flows, redirect URIs, token algorithms.
- **Headers & Cookies** - HTTP security headers, CSP, and cookie attributes.
- **NIS2 Compliance** - Modules mapped to NIS2 Art. 21 obligations.
- **Quick check** - Fastest scan covering the highest-impact checks.

### Module Selection

Individual modules can be toggled. Use **Select all** / **Deselect all** for bulk control. The scan only runs modules that are checked.

### Options

- **Skip TLS verification** - Bypasses certificate validation. Use for internal targets with self-signed certificates.
- **Timeout** - Per-module HTTP request timeout (10-120 seconds). Increase for slow or remote targets.

### Starting and Cancelling

Click **Start Scan** to begin. A progress bar shows completed module checks. Click **Cancel** to abort a running scan.

---

## Understanding Results

### Risk Score

The risk score (0-100) aggregates weighted findings across all severity levels:

- **0-24 - Secure**: few or no significant findings
- **25-49 - Moderate**: issues present, address HIGH findings within 30 days
- **50-74 - At Risk**: significant gaps, address CRITICAL and HIGH findings promptly
- **75-100 - Critical**: immediate remediation required

### Severity Levels

- **CRITICAL** - Exploitable without authentication or with trivial steps. Remediate immediately.
- **HIGH** - Significant risk, likely exploitable with moderate effort.
- **MEDIUM** - Exploitable under specific conditions or combined with other weaknesses.
- **LOW** - Defense-in-depth weaknesses worth addressing in scheduled maintenance.
- **INFO** - Informational observations with no direct attack vector.
- **CHAIN** - Combined risk: two or more co-occurring weaknesses that form an attack path.

### Filtering Findings

Use the severity filter buttons to focus on a specific risk tier. The search box matches against finding title, description, module name, and NIS2 article references.

### Context-Sensitive Help

Click the **?** button on any finding card to open its full documentation page, including technical background, remediation steps, and NIS2 mapping.

---

## Exporting Results

- **HTML** - Formatted report suitable for stakeholders and auditors.
- **JSON** - Machine-readable output for SIEM integration, ticketing systems, or custom tooling.

Both exports re-run the scan against the selected host and modules before generating output.

---

## NIS2 Compliance Guide

The **NIS2 Guide** maps findings to obligations under NIS2 Directive Article 21. Each article page lists the relevant tags and explains which types of findings are covered. Use this view to prepare evidence for compliance assessments or to scope remediation work around regulatory deadlines.

---

## Finding Reference

The **Finding Reference** documents every check the scanner performs, organized by module. Each module page describes what the module does and which checks it runs. Individual finding pages provide:

- **Technical background**: why the finding matters and what an attacker could do
- **Remediation**: specific configuration steps to fix the issue
- **NIS2 mapping**: which Article 21 obligation the finding addresses (where applicable)

Access the Finding Reference from the sidebar, or click **?** on any finding in the Results view to jump directly to that finding's documentation.
