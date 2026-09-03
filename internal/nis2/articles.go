package nis2

import "regexp"

// Article represents one sub-paragraph of NIS2 Directive (EU) 2022/2555 Art. 21(2).
type Article struct {
	ID     string // e.g. "21-2-a"
	Number string // "Art. 21(2)(a)"

	Title         string // short English title
	TitleDE       string // short German title
	DirectiveText   string // verbatim text from Directive (EU) 2022/2555 (EN)
	DirectiveTextDE string // verbatim text from Directive (EU) 2022/2555 (DE)
	ContextNote     string // IAM scanner interpretation (EN)
	ContextNoteDE   string // IAM scanner interpretation (DE)
	Obligations     []string // compliance obligation bullets (EN)
	ObligationsDE   []string // compliance obligation bullets (DE)
}

// GetTitle returns the title in the requested language, falling back to English.
func (a Article) GetTitle(lang string) string {
	if lang == "de" && a.TitleDE != "" {
		return a.TitleDE
	}
	return a.Title
}

// GetDirectiveText returns the directive text in the requested language.
func (a Article) GetDirectiveText(lang string) string {
	if lang == "de" && a.DirectiveTextDE != "" {
		return a.DirectiveTextDE
	}
	return a.DirectiveText
}

// GetContextNote returns the context note in the requested language.
func (a Article) GetContextNote(lang string) string {
	if lang == "de" && a.ContextNoteDE != "" {
		return a.ContextNoteDE
	}
	return a.ContextNote
}

// GetObligations returns the obligation bullets in the requested language.
func (a Article) GetObligations(lang string) []string {
	if lang == "de" && len(a.ObligationsDE) > 0 {
		return a.ObligationsDE
	}
	return a.Obligations
}

// Articles is the ordered catalog of Art. 21(2) sub-paragraphs covered by Idenaro.
var Articles = []Article{
	{
		ID:              "21-2-a",
		Number:          "Art. 21(2)(a)",
		Title:           "Risk Analysis and Information System Security Policies",
		TitleDE:         "Risikoanalyse und Informationssystemsicherheit",
		DirectiveText:   "Policies on risk analysis and information system security.",
		DirectiveTextDE: "Konzepte in Bezug auf die Risikoanalyse und die Sicherheit für Informationssysteme.",
		ContextNote: "Findings mapped to this article indicate configurations that introduce " +
			"unquantified risk or reflect the absence of a deliberate security policy decision " +
			"(e.g. permissive CORS with no allowlist, or chain findings that signal the absence " +
			"of a cohesive security posture across the assessed system).",
		ContextNoteDE: "Befunde zu diesem Artikel weisen auf Konfigurationen hin, die unkalkulierbare " +
			"Risiken einführen oder das Fehlen einer bewussten Sicherheitsentscheidung widerspiegeln " +
			"(z. B. permissive CORS-Konfiguration ohne Allowlist oder Kettenbefunde, die auf eine " +
			"fehlende kohärente Sicherheitslage im bewerteten System hinweisen).",
		Obligations: []string{
			"A formal risk register covering network-facing administrative interfaces and identity infrastructure.",
			"Security policies explicitly defining which origins, networks, and principals may access each system.",
			"Zero-trust architecture decisions documented, with a remediation roadmap if not yet fully implemented.",
			"Risk assessments reviewed at defined intervals and after significant changes.",
		},
		ObligationsDE: []string{
			"Ein formales Risikoregister, das netzwerkseitige Administrationsschnittstellen und Identitätsinfrastruktur abdeckt.",
			"Sicherheitskonzepte, die explizit festlegen, welche Ursprünge, Netzwerke und Principals auf welche Systeme zugreifen dürfen.",
			"Dokumentierte Zero-Trust-Architekturentscheidungen, bei unvollständiger Umsetzung mit Maßnahmenplan.",
			"Überprüfung der Risikobewertungen in definierten Abständen und nach wesentlichen Änderungen.",
		},
	},
	{
		ID:              "21-2-d",
		Number:          "Art. 21(2)(d)",
		Title:           "Supply Chain Security",
		TitleDE:         "Sicherheit der Lieferkette",
		DirectiveText:   "Supply chain security, including security-related aspects concerning the relationships between each entity and its direct suppliers or service providers.",
		DirectiveTextDE: "Sicherheit der Lieferkette einschließlich sicherheitsbezogener Aspekte der Beziehungen zwischen den einzelnen Einrichtungen und ihren unmittelbaren Anbietern oder Diensteanbietern.",
		ContextNote: "SCIM provisioning endpoints are the primary supply chain vector in IAM " +
			"systems - they allow external identity providers and HR systems to create, update, " +
			"and deprovision user accounts. An unauthenticated or over-permissioned SCIM endpoint " +
			"gives any connected supplier the ability to manipulate the identity store.",
		ContextNoteDE: "SCIM-Bereitstellungsendpunkte sind der primäre Lieferketten-Angriffsvektor in IAM-Systemen - " +
			"sie ermöglichen externen Identitätsanbietern und HR-Systemen, Benutzerkonten zu erstellen, zu " +
			"aktualisieren und zu entfernen. Ein nicht authentifizierter oder übermäßig berechtigter SCIM-Endpunkt " +
			"gibt jedem angeschlossenen Lieferanten die Möglichkeit, den Identitätsspeicher zu manipulieren.",
		Obligations: []string{
			"SCIM provisioning endpoints must require authentication and be restricted to authorised network ranges.",
			"Third-party access to identity management systems must be individually audited, scoped, and minimised.",
			"Supplier security practices must be assessed during onboarding and reviewed periodically.",
			"Contracts with identity providers and HR system vendors must include Art. 21 security requirements.",
		},
		ObligationsDE: []string{
			"SCIM-Bereitstellungsendpunkte müssen Authentifizierung erfordern und auf autorisierte Netzwerkbereiche beschränkt sein.",
			"Drittanbieterzugriff auf Identitätsmanagementsysteme muss einzeln geprüft, abgegrenzt und minimiert werden.",
			"Sicherheitspraktiken von Lieferanten müssen beim Onboarding bewertet und regelmäßig überprüft werden.",
			"Verträge mit Identitätsanbietern und HR-Systemanbietern müssen die Sicherheitsanforderungen des Art. 21 umfassen.",
		},
	},
	{
		ID:              "21-2-e",
		Number:          "Art. 21(2)(e)",
		Title:           "Security in Network and Information Systems Acquisition, Development and Maintenance",
		TitleDE:         "Sicherheit bei Erwerb, Entwicklung und Wartung",
		DirectiveText:   "Security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure.",
		DirectiveTextDE: "Sicherheit bei Erwerb, Entwicklung und Wartung von Netz- und Informationssystemen, einschließlich Management und Offenlegung von Schwachstellen.",
		ContextNote: "Findings in this category include missing or misconfigured HTTP security " +
			"headers (HSTS, X-Frame-Options, X-Content-Type-Options), absent Content Security " +
			"Policy, CORS policies allowing unintended origins, insecure cookie attributes, open " +
			"redirect vulnerabilities in authentication flows, user enumeration weaknesses, and " +
			"exposed debug or management endpoints that should have been disabled before deployment.",
		ContextNoteDE: "Befunde dieser Kategorie umfassen fehlende oder fehlkonfigurierte HTTP-Sicherheits-Header " +
			"(HSTS, X-Frame-Options, X-Content-Type-Options), fehlende Content Security Policy, CORS-Richtlinien " +
			"mit unbeabsichtigten Ursprüngen, unsichere Cookie-Attribute, Open-Redirect-Schwachstellen in " +
			"Authentifizierungsabläufen, Schwachstellen bei der Benutzeraufzählung sowie exponierte Debug- oder " +
			"Verwaltungsendpunkte, die vor der Produktivsetzung hätten deaktiviert werden müssen.",
		Obligations: []string{
			"Security headers must be part of the standard deployment baseline, not optional post-launch additions.",
			"CORS and CSP policies must be reviewed and hardened as part of each release cycle.",
			"Authentication flows must be tested for open redirect and enumeration vulnerabilities before deployment.",
			"Debug endpoints, actuator interfaces, and development tooling must be disabled or removed in production builds.",
			"Cookie security attributes (Secure, HttpOnly, SameSite) must be enforced at the framework level.",
		},
		ObligationsDE: []string{
			"Sicherheits-Header müssen Teil der Standard-Deployment-Baseline sein, keine optionalen Nachbesserungen.",
			"CORS- und CSP-Richtlinien müssen als Teil jedes Release-Zyklus überprüft und gehärtet werden.",
			"Authentifizierungsabläufe müssen vor dem Deployment auf Open-Redirect- und Enumeration-Schwachstellen getestet werden.",
			"Debug-Endpunkte, Actuator-Schnittstellen und Entwicklungs-Tools müssen in Produktions-Builds deaktiviert oder entfernt sein.",
			"Cookie-Sicherheitsattribute (Secure, HttpOnly, SameSite) müssen auf Framework-Ebene erzwungen werden.",
		},
	},
	{
		ID:              "21-2-g",
		Number:          "Art. 21(2)(g)",
		Title:           "Basic Cyber Hygiene Practices and Cybersecurity Training",
		TitleDE:         "Grundlegende Cyberhygiene und Schulungen",
		DirectiveText:   "Basic cyber hygiene practices and cybersecurity training.",
		DirectiveTextDE: "Grundlegende Verfahren im Bereich der Cyberhygiene und Schulungen im Bereich der Cybersicherheit.",
		ContextNote: "Findings in this category indicate the absence of controls widely considered " +
			"baseline security practice, expected regardless of organisation size or sector: " +
			"missing security headers, absent CSP on authentication interfaces, exposed management " +
			"endpoints, and account lifecycle issues.",
		ContextNoteDE: "Befunde dieser Kategorie weisen auf das Fehlen von Kontrollen hin, die unabhängig " +
			"von Organisationsgröße oder Branche als grundlegende Sicherheitspraxis gelten: fehlende " +
			"Sicherheits-Header, fehlende CSP auf Authentifizierungsschnittstellen, exponierte " +
			"Verwaltungsendpunkte und Schwachstellen im Kontolebenszyklus.",
		Obligations: []string{
			"A defined set of baseline security controls must be applied to all production systems as a matter of routine.",
			"Account lifecycle management must include documented procedures for provisioning, review, and deprovisioning.",
			"Technical staff with access to identity infrastructure must receive regular cybersecurity training.",
			"Cyber hygiene checklists must be part of deployment sign-off processes.",
		},
		ObligationsDE: []string{
			"Ein definierter Satz von Baseline-Sicherheitskontrollen muss routinemäßig auf alle Produktivsysteme angewendet werden.",
			"Das Kontolebenszyklus-Management muss dokumentierte Verfahren für Bereitstellung, Überprüfung und Deprovisionierung umfassen.",
			"Technisches Personal mit Zugang zur Identitätsinfrastruktur muss regelmäßige Cybersicherheitsschulungen erhalten.",
			"Cyberhygiene-Checklisten müssen Teil der Abnahme-Prozesse bei Deployments sein.",
		},
	},
	{
		ID:              "21-2-h",
		Number:          "Art. 21(2)(h)",
		Title:           "Policies and Procedures Regarding Cryptography and Encryption",
		TitleDE:         "Kryptografie und Verschlüsselung",
		DirectiveText:   "Policies and procedures regarding the use of cryptography and, where appropriate, encryption.",
		DirectiveTextDE: "Konzepte und Verfahren für den Einsatz von Kryptografie und gegebenenfalls Verschlüsselung.",
		ContextNote: "Findings include broken or outdated TLS configuration (expired certificates, " +
			"deprecated TLS 1.0/1.1, weak cipher suites), session cookies transmitted without the " +
			"Secure flag, and token security weaknesses involving weak signing algorithms or " +
			"insufficient entropy.",
		ContextNoteDE: "Befunde umfassen fehlerhafte oder veraltete TLS-Konfigurationen (abgelaufene Zertifikate, " +
			"veraltetes TLS 1.0/1.1, schwache Cipher-Suites), Session-Cookies ohne Secure-Flag sowie " +
			"Tokensicherheitsschwächen durch schwache Signaturalgorithmen oder unzureichende Entropie.",
		Obligations: []string{
			"All authentication traffic must be encrypted using current TLS standards (minimum TLS 1.2, prefer TLS 1.3).",
			"HSTS must be deployed with a minimum max-age of 31,536,000 seconds to prevent SSL stripping.",
			"Session tokens must be protected via the Secure cookie flag and HTTPS-only configuration.",
			"Token signing must use approved algorithms (RS256, ES256 minimum) with appropriate key lengths.",
			"A cryptographic policy document must define approved algorithms, key lengths, and rotation schedules.",
		},
		ObligationsDE: []string{
			"Der gesamte Authentifizierungsverkehr muss mit aktuellen TLS-Standards verschlüsselt sein (mindestens TLS 1.2, bevorzugt TLS 1.3).",
			"HSTS muss mit einem max-age von mindestens 31.536.000 Sekunden eingesetzt werden, um SSL-Stripping zu verhindern.",
			"Session-Tokens müssen durch das Secure-Cookie-Flag und eine HTTPS-only-Konfiguration geschützt sein.",
			"Token-Signierung muss zugelassene Algorithmen verwenden (mindestens RS256, ES256) mit angemessenen Schlüssellängen.",
			"Ein Kryptografie-Richtliniendokument muss zugelassene Algorithmen, Schlüssellängen und Rotationspläne definieren.",
		},
	},
	{
		ID:              "21-2-i",
		Number:          "Art. 21(2)(i)",
		Title:           "Human Resources Security, Access Control Policies and Asset Management",
		TitleDE:         "Personalsicherheit, Zugriffskontrolle und Asset-Management",
		DirectiveText:   "Human resources security, access control policies and asset management.",
		DirectiveTextDE: "Sicherheit des Personals, Konzepte für die Zugriffskontrolle und Management von Anlagen.",
		ContextNote: "This is the broadest IAM-specific category: insecure OAuth2 flows, SAML " +
			"assertion signing failures, OIDC algorithm weaknesses, user enumeration vulnerabilities, " +
			"open redirect attacks on authentication flows, exposed SCIM provisioning endpoints, " +
			"admin panel exposure, zero-trust gaps, token leakage, and lifecycle management failures.",
		ContextNoteDE: "Dies ist die breiteste IAM-spezifische Kategorie: unsichere OAuth2-Abläufe, Fehler bei " +
			"der SAML-Assertion-Signierung, OIDC-Algorithmus-Schwachstellen, Benutzeraufzählungs-Schwachstellen, " +
			"Open-Redirect-Angriffe auf Authentifizierungsabläufe, exponierte SCIM-Bereitstellungsendpunkte, " +
			"Admin-Panel-Exposition, Zero-Trust-Lücken, Token-Leakage und Lifecycle-Management-Fehler.",
		Obligations: []string{
			"Access control policies must define roles, permissions, and review cycles for all identity infrastructure.",
			"Authentication protocols must use current secure flows: Authorization Code + PKCE for OIDC, signed assertions for SAML.",
			"Identity provisioning (SCIM) must be protected by authentication and restricted to authorised systems.",
			"Access tokens and credentials must never be transmitted through browser-facing channels (URL fragments, localStorage).",
			"Password reset and authentication flows must not reveal account existence information.",
			"Asset inventory must include all identity systems, with access reviewed at defined intervals.",
		},
		ObligationsDE: []string{
			"Zugriffskontrollkonzepte müssen Rollen, Berechtigungen und Überprüfungszyklen für alle Identitätsinfrastruktur definieren.",
			"Authentifizierungsprotokolle müssen aktuelle sichere Abläufe nutzen: Authorization Code + PKCE für OIDC, signierte Assertions für SAML.",
			"Identity Provisioning (SCIM) muss durch Authentifizierung geschützt und auf autorisierte Systeme beschränkt sein.",
			"Zugriffstoken und Anmeldedaten dürfen niemals über browserseitige Kanäle übertragen werden (URL-Fragmente, localStorage).",
			"Passwort-Reset- und Authentifizierungsabläufe dürfen keine Informationen über die Existenz von Konten preisgeben.",
			"Das Asset-Inventar muss alle Identitätssysteme umfassen, mit Zugriffsprüfungen in definierten Abständen.",
		},
	},
	{
		ID:              "21-2-j",
		Number:          "Art. 21(2)(j)",
		Title:           "Multi-Factor Authentication and Secured Communications",
		TitleDE:         "Multi-Faktor-Authentifizierung und sichere Kommunikation",
		DirectiveText:   "The use of multi-factor authentication or continuous authentication solutions, secured voice, video and text communications and secured emergency communication systems within the entity, where appropriate.",
		DirectiveTextDE: "Verwendung von Lösungen zur Multi-Faktor-Authentifizierung oder kontinuierlichen Authentifizierung, gesicherte Sprach-, Video- und Textkommunikation sowie gegebenenfalls gesicherte Notfallkommunikationssysteme innerhalb der Einrichtung.",
		ContextNote: "Findings include: no MFA detected on login flows, authentication protocols " +
			"(OIDC, SAML) configured in ways that bypass or weaken multi-factor requirements, TLS " +
			"weaknesses that undermine the security of authenticated sessions, and insecure token " +
			"transmission that defeats the purpose of strong authentication.",
		ContextNoteDE: "Befunde umfassen: keine MFA auf Anmeldeabläufen erkannt, Authentifizierungsprotokolle " +
			"(OIDC, SAML), die Multi-Faktor-Anforderungen umgehen oder schwächen, TLS-Schwachstellen, die die " +
			"Sicherheit authentifizierter Sitzungen untergraben, sowie unsichere Token-Übertragung, die den Zweck " +
			"starker Authentifizierung zunichte macht.",
		Obligations: []string{
			"MFA must be enforced for all access to network and information systems.",
			"OIDC implementations must use Authorization Code + PKCE; implicit and ROPC flows must be disabled.",
			"SAML assertions must be signed and encrypted; unsigned assertions must be rejected.",
			"Session security must be maintained end-to-end: MFA at login is insufficient if the session token is transmitted insecurely.",
			"Zero-trust architectures must enforce step-up or continuous authentication for sensitive operations.",
		},
		ObligationsDE: []string{
			"MFA muss für alle Zugriffe auf Netz- und Informationssysteme erzwungen werden.",
			"OIDC-Implementierungen müssen Authorization Code + PKCE verwenden; Implicit- und ROPC-Flows müssen deaktiviert sein.",
			"SAML-Assertions müssen signiert und verschlüsselt sein; nicht signierte Assertions müssen abgelehnt werden.",
			"Die Sitzungssicherheit muss durchgängig gewährleistet sein: MFA beim Login ist unzureichend, wenn das Session-Token unsicher übertragen wird.",
			"Zero-Trust-Architekturen müssen Step-up- oder kontinuierliche Authentifizierung für sensible Operationen erzwingen.",
		},
	},
}

var nis2RefRE = regexp.MustCompile(`Art\. 21 \(2\)\(([a-j])\)`)

// RefToID converts any NIS2 article reference string to its canonical ID
// (e.g. "21-2-i"). Works for both the English format used by the engine's
// post-processor and the German-language format used by the client module.
func RefToID(ref string) string {
	m := nis2RefRE.FindStringSubmatch(ref)
	if len(m) < 2 {
		return ""
	}
	return "21-2-" + m[1]
}

// FindByID returns the Article with the given ID. The second return value is
// false if no matching article is found.
func FindByID(id string) (Article, bool) {
	for _, a := range Articles {
		if a.ID == id {
			return a, true
		}
	}
	return Article{}, false
}
