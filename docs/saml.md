## saml-overview | SAML | 

The SAML module inspects SAML Identity Provider and Service Provider configurations by fetching and parsing publicly accessible metadata documents. It analyzes signature requirements, certificate health, binding choices, and single logout configuration without credentials.

### Checks performed

- Metadata document accessibility and structure
- Signed AuthnRequest requirement at the IdP
- SSO and ACS endpoint HTTPS enforcement
- Binding types in use: HTTP-Redirect, SOAP, Artifact
- SP signature and encryption key configuration
- Certificate expiry, short validity, and reuse between signing and encryption
- Single Logout (SLO) endpoint presence

---

## saml-metadata | SAML Metadata Publicly Accessible | INFO

SAML metadata is accessible without authentication. This is expected for federated SSO but exposes IdP and SP configuration, endpoint URLs, and signing certificates. Verify the disclosed information is intentional and all certificates are current.

### What to check

- Confirm certificates have not expired or are not expiring soon.
- Verify all endpoint URLs use HTTPS.
- Check that no sensitive internal hostnames appear in the metadata.

---

## saml-unsigned-authn | SAML IdP Does Not Require Signed AuthnRequests | MEDIUM

`WantAuthnRequestsSigned=false` means the IdP accepts unsigned authentication requests. Attackers can forge authentication requests, manipulate NameID formats, request unwanted attributes, or abuse ForceAuthn to bypass existing sessions.

### Remediation

- Set `WantAuthnRequestsSigned="true"` in the IdP configuration.
- Ensure all SPs sign their AuthnRequests and that the IdP validates signatures.

---

## saml-sso-http | SAML SSO Endpoint Does Not Use HTTPS | HIGH

The SingleSignOnService endpoint uses HTTP. SAML assertions transmitted over HTTP are visible to network observers and can be intercepted and replayed by attackers on the same network.

### Remediation

- Configure all SAML endpoints to use HTTPS only.
- Redirect HTTP requests to HTTPS with a 301 permanent redirect.

---

## saml-redirect-binding | SAML HTTP-Redirect Binding in Use | LOW

The HTTP-Redirect binding transmits SAML messages as URL query parameters. This limits message size and exposes encoded assertions to server logs and browser history. HTTP-POST binding is preferred for responses.

### Remediation

- Use HTTP-POST binding for SingleSignOnService responses.
- HTTP-Redirect is acceptable for AuthnRequests from the SP, but not for IdP responses containing assertions.

---

## saml-soap-binding | SAML SOAP Binding Exposed | LOW

The SOAP binding is listed in SAML metadata. SOAP bindings are uncommon in modern deployments, expand the attack surface, and often indicate legacy configuration. Misconfigured SOAP endpoints can be abused for SSRF.

### Remediation

- Remove SOAP binding unless explicitly required by a federation partner.
- Audit the SOAP endpoint for authentication requirements and access controls.

---

## saml-artifact-binding | SAML Artifact Binding Exposed | LOW

The Artifact binding requires the SP to resolve artifacts via a back-channel request to the IdP's ArtifactResolutionService. Misconfigured artifact resolution endpoints can be abused for SSRF, and the binding adds complexity that is rarely justified.

### Remediation

- Remove Artifact binding unless specifically required.
- If used, ensure the ArtifactResolutionService requires mutual TLS or client authentication.

---

## saml-sp-unsigned-assertions | SAML SP Does Not Require Signed Assertions | HIGH

`WantAssertionsSigned=false` means the SP accepts SAML assertions without verifying their signature. An attacker who can intercept or inject an assertion can authenticate as any user without a valid IdP signature.

### Remediation

- Set `WantAssertionsSigned="true"` in SP metadata.
- Configure the IdP to always sign assertions for this SP.
- Verify both assertion-level and response-level signing are enforced.

---

## saml-sp-unsigned-authn | SAML SP Does Not Sign AuthnRequests | MEDIUM

The SP does not sign outbound authentication requests (`AuthnRequestsSigned=false`). Unsigned requests allow man-in-the-middle manipulation of NameID format, ForceAuthn flags, and requested attribute sets.

### Remediation

- Enable request signing on the SP and set `AuthnRequestsSigned="true"`.
- Configure the IdP to validate request signatures from this SP.

---

## saml-no-encryption-key | SAML SP Has No Encryption Key | MEDIUM

The SP metadata contains no encryption key descriptor. The IdP cannot encrypt assertions, meaning user identity attributes and role claims are transmitted in plaintext. If TLS is degraded or an intermediary is compromised, attributes are exposed.

### Remediation

- Add an encryption key descriptor to the SP metadata.
- Configure the IdP to encrypt assertions using the SP's public key.
- Use separate key pairs for signing and encryption.

---

## saml-acs-http | SAML ACS Endpoint Does Not Use HTTPS | HIGH

The AssertionConsumerService endpoint uses HTTP. SAML assertions POSTed to this endpoint are transmitted in cleartext, exposing user identity attributes, session tokens, and role claims to network observers.

### Remediation

- Serve the ACS endpoint over HTTPS only.
- Update SP metadata to reflect the HTTPS ACS URL.
- Redirect any HTTP ACS requests to HTTPS.

---

## saml-cert-expired | SAML Signing Certificate Expired | HIGH

The SAML signing certificate in the metadata has expired. This causes all federation to fail for IdPs that enforce certificate validity. Some permissive implementations may fall back to accepting unsigned assertions, creating a security gap.

### Remediation

- Generate a new certificate immediately.
- Use rolling rotation: publish the new certificate in metadata before activating it for signing.
- Update all SP metadata and federation partner configurations.
- Rotate within your scheduled maintenance window to minimize downtime.

---

## saml-cert-expiring | SAML Signing Certificate Expiring Soon | MEDIUM

The SAML signing certificate expires within 30 days. Failure to rotate before expiry will cause authentication outages for all federated services relying on this certificate.

### Remediation

- Begin certificate rotation immediately - plan for the full rollout including partner metadata updates.
- Implement automated certificate expiry monitoring and alerting at 60, 30, and 7 days.

---

## saml-cert-long-lived | SAML Certificate Has Very Long Validity | LOW

The SAML signing certificate has a validity period greater than 3 years. Long-lived certificates increase the impact window if the private key is compromised - the key remains usable for signing tokens for the entire validity period.

### Remediation

- Issue new certificates with a maximum 2-year validity period.
- Implement automated rotation on a scheduled basis (annually recommended).

---

## saml-same-cert | SAML Same Certificate for Signing and Encryption | LOW

The signing and encryption key descriptors reference the same certificate. Best practice requires separate keys: compromise of the signing key also compromises assertion confidentiality, and compromise of the encryption key could be used for forgery.

### Remediation

- Generate separate key pairs for signing and encryption.
- Update both IdP configuration and SP metadata to use the separate keys.

---

## saml-no-slo | SAML Single Logout Not Configured | MEDIUM

No Single Logout (SLO) service is configured in the IdP metadata. Without SLO, logging out of the IdP does not terminate sessions at connected Service Providers, leaving users authenticated at SPs even after they believe they have logged out.

### Remediation

- Configure an SLO endpoint in the IdP metadata.
- Ensure all SPs implement SLO handling and respond to logout requests.
- Test the complete logout flow across all registered SPs.
