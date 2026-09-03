## tls-overview | TLS | 

The TLS module inspects the transport layer security configuration of authentication endpoints. It validates certificate health, negotiates TLS connections to verify protocol version and cipher suite strength, and checks HTTPS enforcement across the authentication surface.

### Checks performed

- Certificate expiry: expired and expiring within 30 days
- Self-signed certificates not trusted by public CAs
- Certificate hostname mismatch against the target
- Internal hostname in certificate Subject Alternative Names (SAN)
- Deprecated TLS protocol version negotiated: SSLv3, TLS 1.0, TLS 1.1
- HTTP responding without redirect to HTTPS
- Mixed content (HTTP sub-resources) on HTTPS auth pages
- Weak cipher suites: RC4, 3DES, export-grade
- Cipher suites without forward secrecy (non-ECDHE/DHE)
- OCSP stapling absent

---

## tls-expired | TLS Certificate Expired | CRITICAL

The TLS certificate has expired. Browsers display security warnings and many clients refuse to connect entirely. Users who click through warnings train themselves to accept certificate errors, weakening security culture. This must be remediated immediately.

### Remediation

- Renew the certificate immediately.
- Use Let's Encrypt with certbot and automated renewal hooks.
- Set up monitoring to alert at 30 days and 7 days before expiry.

---

## tls-expiring | TLS Certificate Expiring Soon | HIGH

The TLS certificate expires within 30 days. Failure to renew will cause browser security warnings and connection failures for all clients that enforce certificate validity.

### Remediation

- Renew the certificate before expiry.
- Implement automated renewal (Let's Encrypt, ACME protocol).

---

## tls-self-signed | Self-Signed Certificate | HIGH

The certificate is self-signed and not trusted by any browser or OS by default. Users see security warnings and must manually accept. Automated clients and monitoring systems fail to connect. Self-signed certs on production auth portals indicate absent certificate management processes.

### Remediation

- Replace with a certificate from a trusted CA (Let's Encrypt, DigiCert, Sectigo).
- For internal services, operate an internal CA and deploy the root via MDM or Group Policy.

---

## tls-hostname-mismatch | TLS Certificate Hostname Mismatch | HIGH

The certificate is not valid for the target hostname. This typically indicates a misconfigured reverse proxy serving an internal certificate on a public endpoint, or a certificate issued for the wrong hostname.

### Remediation

- Issue a certificate that includes the correct hostname in the Subject Alternative Names.
- Verify reverse proxy TLS termination is configured with the correct certificate.

---

## tls-internal-san | Internal Hostname in TLS Certificate SAN | MEDIUM

The certificate SAN includes internal hostnames (.internal, .local, .corp, Kubernetes service names). These are permanently logged in Certificate Transparency logs, permanently disclosing internal network topology to anyone who searches CT logs.

### Remediation

- Issue separate certificates for internal and external hostnames.
- Do not include internal DNS names in certificates used on public endpoints.

---

## tls-deprecated-version | Deprecated TLS Version Negotiated | HIGH

The server negotiated TLS 1.0 or 1.1, which are deprecated and vulnerable to POODLE, BEAST, and downgrade attacks. Auth portals must use TLS 1.2 at minimum, with TLS 1.3 preferred.

### Remediation

- Disable TLS 1.0 and 1.1 in your web server configuration.
- Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`
- Apache: `SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1`

---

## tls-no-https-redirect | HTTP Responds Without HTTPS Redirect | HIGH

The server responds to plain HTTP requests without redirecting to HTTPS. Users who visit the HTTP URL have their session credentials and tokens transmitted in cleartext.

### Remediation

- Redirect all HTTP traffic to HTTPS with a 301 permanent redirect.
- Combine with HSTS to prevent future HTTP access.

---

## tls-mixed-content | Mixed Content on Auth Page | MEDIUM

The HTTPS login page references HTTP resources (scripts, stylesheets, images). Modern browsers block mixed content, causing functionality issues. HTTP resources on an HTTPS page can be intercepted and substituted by a network attacker.

### Remediation

- Replace all HTTP resource references with HTTPS equivalents.
- Use protocol-relative URLs or absolute HTTPS URLs for all resources.
- Add a CSP `upgrade-insecure-requests` directive as a fallback.

---

## tls-weak-cipher | Weak Cipher Suite Negotiated | HIGH

The server negotiated a cipher suite using RC4, 3DES, or another deprecated algorithm. RC4 is broken and 3DES is vulnerable to the SWEET32 birthday attack. These ciphers must not be used on authentication infrastructure.

### Remediation

- Disable all RC4, 3DES, and NULL cipher suites.
- Use a modern cipher suite list: ECDHE+AESGCM, ECDHE+CHACHA20.
- Test with ssl-labs.com and target an A+ rating.

---

## tls-no-forward-secrecy | Cipher Suite Without Forward Secrecy | HIGH

The server negotiated a cipher suite using RSA key exchange (no forward secrecy). If the server's private key is ever compromised, all past recorded TLS sessions can be decrypted retroactively.

### Remediation

- Prioritize ECDHE cipher suites which provide forward secrecy.
- Disable RSA key exchange cipher suites.

---

## tls-no-ocsp | OCSP Stapling Absent | LOW

OCSP stapling is not configured. Without it, browsers must make a separate real-time request to the CA's OCSP server to verify certificate revocation status. This adds latency and creates a privacy leak (revealing which sites the user visits to the CA).

### Remediation

- Nginx: `ssl_stapling on; ssl_stapling_verify on;`
- Apache: `SSLUseStapling on`
