Chain findings represent a combined risk spanning multiple Article 21(2) requirements simultaneously. When two or more related misconfigurations are detected together, the combination creates a risk greater than the sum of its parts - and maps to multiple specific articles: supply chain security (d), secure development (e), and risk analysis (a).

### Why combined risks matter for NIS2

NIS2 Art. 21(1) requires entities to take "appropriate and proportionate technical, operational and organisational measures to manage the risks posed to the security of network and information systems". The word "appropriate" implies that context matters - a single missing header might be acceptable, but the same missing header combined with an exposed admin panel and absent MFA constitutes a systemic failure that NIS2 explicitly addresses.

### Examples of chain conditions

- **Missing MFA + exposed admin panel:** A single compromised password grants full administrative access. Art. 21(2)(i) and (j) require both access control and MFA - their combined absence is a critical compliance gap.
- **CORS misconfiguration + auth endpoint:** Crosses Art. 21(2)(e) (secure development) and Art. 21(2)(i) (access control) simultaneously.
- **Implicit flow + weak CSP:** An XSS vulnerability (Art. 21(2)(e)) combined with tokens in URL fragments (Art. 21(2)(i)) creates a token theft attack chain.

### Remediation priority

Chain findings should be treated as the highest remediation priority. Address all contributing findings together as a coordinated effort rather than individually, since fixing one component while leaving others open may provide a false sense of security without meaningfully reducing the attack surface.
