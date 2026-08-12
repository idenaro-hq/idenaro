## oidc-overview | OIDC / OAuth2 | 

Das OIDC/OAuth2-Modul analysiert OpenID-Connect- und OAuth-2.0-Identity-Provider-Konfigurationen. Es ruft das `/.well-known/openid-configuration`-Discovery-Dokument ab und prüft unterstützte Flows, Signaturalgorithmen, Redirect-URI-Registrierungen und erweiterte Sicherheitsfunktionen - alles ohne Zugangsdaten.

### Durchgeführte Prüfungen

- Zugänglichkeit und Inhalt des Discovery-Dokuments
- Unterstützte Grant-Typen: Implicit Flow, Hybrid Flow, ROPC, Device Authorization
- PKCE-Unterstützung und S256-Methoden-Durchsetzung
- Token-Signaturalgorithmus-Sicherheit (alg=none, symmetrisches HS256)
- Issuer-Validierung: HTTPS-Durchsetzung, Host-Matching, internes Hostname-Leck
- Endpunkt-HTTPS-Durchsetzung für alle beworbenen URLs
- Redirect-URI-Sicherheit: Wildcards, HTTP-URIs, Localhost, IP-Adressen
- Erweiterte Features: PAR, JAR, Vorhandensein des Token-Revocation-Endpunkts
- Client-Authentifizierungsanforderungen am Token-Endpunkt

---

## oidc-discovery | OIDC-Discovery-Endpunkt Exponiert | INFO

Das OpenID-Connect-Discovery-Dokument unter `/.well-known/openid-configuration` ist öffentlich zugänglich. Dies ist gemäß der OIDC-Spezifikation erwartet, legt aber die vollständige IdP-Konfiguration einschließlich Endpunkt-URLs, unterstützter Algorithmen und Grant-Typen offen.

### Was zu prüfen ist

- Sicherstellen, dass keine internen Hostnamen, privaten IPs oder Staging-Domainnamen in Endpunkt-URLs erscheinen.
- Überprüfen, dass der Issuer exakt mit dem öffentlich zugänglichen Hostnamen übereinstimmt.
- Bestätigen, dass keine schwachen Algorithmen oder unsicheren Flows beworben werden.

---

## oidc-implicit | Impliziter Flow Aktiviert | MEDIUM

Der implizite OAuth2-Flow (`response_type=token` oder `response_type=id_token`) gibt Tokens direkt im URL-Fragment nach der Autorisierung zurück. Diese Tokens sind im Browser-Verlauf, Server-Zugriffsprotokollen und HTTP-Referer-Headern sichtbar. Der Flow ist in OAuth 2.1 als veraltet eingestuft.

### Behebung

- `response_type=token` und `response_type=id_token` im IdP deaktivieren.
- Alle Clients auf Authorization-Code-Flow mit PKCE (RFC 7636) migrieren.
- Keycloak: Realm → Clients → Client → „Implicit Flow Enabled" deaktivieren.

---

## oidc-hybrid | Hybrid-Flow Aktiviert | MEDIUM

Der Hybrid-Flow (`code token` oder `code id_token`) mischt Authorization-Code- und Token-Antworten. Im Front-Channel via URL-Fragment zurückgegebene Tokens umgehen PKCE-Schutzmaßnahmen und erzeugen Token-Leck-Risiken, auch wenn der Code-Flow aktiv ist.

### Behebung

- Hybrid-Flows deaktivieren und reinen Authorization-Code + PKCE verwenden.
- Sicherstellen, dass keine `response_type`-Kombinationen `token` oder `id_token` neben `code` enthalten.

---

## oidc-multi-insecure | Mehrere Unsichere Flows Aktiviert | HIGH

Zwei oder mehr unsichere Response-Typen (Implicit, Hybrid) sind gleichzeitig aktiv. Jeder erhöht die Angriffsfläche; zusammen steigern sie deutlich die Wahrscheinlichkeit, dass Tokens durch Front-Channel-Lecks beschafft werden können.

### Behebung

- Alle Flows außer `code` deaktivieren.
- PKCE-Anforderung für alle Code-Flows aktivieren.
- Alle registrierten Clients prüfen und ungenutzte response_type-Grants entfernen.

---

## oidc-ropc | ROPC-Grant Aktiviert | HIGH

Der Resource-Owner-Password-Credentials-Grant (`password`) erlaubt Clients, Benutzer-Credentials direkt zu sammeln und gegen Tokens einzutauschen. Dies umgeht vollständig MFA, browserbasierte Authentifizierung und Conditional-Access-Richtlinien. In OAuth 2.1 als veraltet eingestuft.

### Behebung

- Den `password`-Grant-Typ im IdP deaktivieren.
- ROPC-Clients auf Authorization-Code + PKCE migrieren.
- Keycloak: Clients → Client → „Direct Access Grants" deaktivieren.

---

## oidc-device-flow | Device-Authorization-Grant Aktiviert | MEDIUM

Der Device-Authorization-Grant (Device Flow) ist für eingabebeschränkte Geräte konzipiert. Auf öffentlich zugänglichen IAM-Systemen wird er für Device-Code-Phishing-Angriffe missbraucht, bei denen Angreifer Benutzer dazu bringen, angreifer-kontrollierte Gerätesitzungen zu autorisieren.

### Behebung

- Device Flow deaktivieren, sofern er nicht für legitime Geräteclients benötigt wird.
- Falls erforderlich: auf spezifische, registrierte Client-IDs beschränken. Nicht öffentlich bewerben.
- Kurze Ablaufzeit für Device Codes implementieren (max. 5 Minuten).

---

## oidc-fragment-mode | Fragment response_mode Unterstützt | LOW

Der Fragment-Response-Modus überträgt Tokens und Codes im URL-Hash-Fragment. Hash-Fragmente sind für JavaScript zugänglich, werden im Browser-Verlauf protokolliert und können über den Referer-Header an externe Ressourcen der Redirect-Seite geleakt werden.

### Behebung

- `form_post`-Response-Modus für alle Autorisierungsantworten bevorzugen.
- Falls Fragment-Modus erforderlich, sicherstellen, dass Redirect-Seiten keine externen Ressourcen laden, die das Fragment lesen könnten.

---

## oidc-pkce | PKCE Nicht Unterstützt | MEDIUM

Proof Key for Code Exchange (RFC 7636) verhindert Authorization-Code-Abfangeangriffe, indem der Autorisierungscode an einen kryptografischen Prüfwert gebunden wird, der nur dem legitimen Client bekannt ist. Ohne PKCE können abgefangene Codes von einem Angreifer gegen Tokens eingetauscht werden.

### Behebung

- PKCE mit der S256-Methode im IdP aktivieren.
- PKCE für alle öffentlichen Clients (SPAs, mobile Apps) erfordern.
- Keycloak 21+: PKCE ist standardmäßig aktiviert. Für ältere Versionen „PKCE Code Challenge Method" pro Client setzen.

---

## oidc-pkce-plain | PKCE S256 Nicht Unterstützt (Nur Plain) | LOW

Nur die `plain`-PKCE-Methode wird unterstützt. Die plain-Methode überträgt den Code-Verifier im Klartext während des Token-Austauschs und bietet schwächeren Schutz als S256, das den Verifier vor der Übertragung hasht.

### Behebung

- `S256` aktivieren und `plain` deaktivieren oder deprioritisieren.
- S256 für alle neuen Clients erfordern.

---

## oidc-alg-none | Algorithmus alg=none Erlaubt | CRITICAL

`alg=none` deaktiviert die JWT-Signaturverifizierung vollständig. Jeder Client kann ein Token fälschen, indem er den Algorithmus auf `none` setzt und die Signatur entfernt. Dies ist ein vollständiger Authentifizierungs-Bypass.

### Behebung

- `none` sofort aus `id_token_signing_alg_values_supported` entfernen.
- Verifizieren, dass die Token-Validierungsbibliothek `alg=none` explizit ablehnt.
- Nach der Änderung alle vorhandenen Tokens rotieren.

---

## oidc-alg-symmetric | Symmetrischer Signaturalgorithmus (HS256) | MEDIUM

Symmetrische Algorithmen (HS256, HS384, HS512) erfordern die Verteilung des Signierschlüssels an alle Token-Validatoren. Dies erzeugt ein Schlüsselmanagement-Risiko und ermöglicht Algorithm-Confusion-Angriffe, bei denen ein öffentlicher Schlüssel als HMAC-Geheimnis verwendet wird.

### Behebung

- Asymmetrische Algorithmen verwenden: RS256 oder ES256.
- Keycloak: Realm-Einstellungen → Tokens → Standard-Signaturalgorithmus → RS256.
- Falls HS256 für Legacy-Clients erforderlich, auf spezifische Clients beschränken.

---

## oidc-issuer-https | OIDC-Issuer Verwendet Kein HTTPS | HIGH

Der Issuer-Wert im Discovery-Dokument verwendet kein HTTPS. Gemäß RFC 8414 muss der Issuer eine `https://`-URI sein. Clients, die den Issuer validieren, lehnen Tokens ab, und Clients, die dies nicht tun, akzeptieren Tokens aus nicht authentifizierten Quellen.

### Behebung

- Die öffentliche URL des IdP auf eine `https://`-URI setzen.
- Keycloak: `KC_HOSTNAME` oder `--hostname` auf den öffentlichen HTTPS-Hostnamen setzen.

---

## oidc-issuer-mismatch | OIDC-Issuer Host-Mismatch | MEDIUM

Das Discovery-Dokument wird von einem anderen Host bereitgestellt als der `issuer`-Wert. Dies zeigt ein defektes Reverse-Proxy-Setup, eine Split-DNS-Fehlkonfiguration oder eine unvollständige Migration an. Clients, die Issuer-Binding validieren, schlagen fehl.

### Behebung

- Sicherstellen, dass der konfigurierte öffentliche Hostname des IdP mit der URL übereinstimmt, von der das Discovery-Dokument bereitgestellt wird.
- X-Forwarded-Host-Header-Rewriting des Reverse-Proxys korrigieren.
- Keycloak: `KC_HOSTNAME` muss mit dem externen Load-Balancer-Hostnamen übereinstimmen.

---

## oidc-internal-leak | Discovery-Dokument Enthält Internen Hostnamen | MEDIUM

Das OIDC-Discovery-Dokument referenziert interne Hostnamen (localhost, private IPs, .internal, .corp, Kubernetes-Dienstnamen, Staging-Domains). Diese werden dauerhaft in Certificate-Transparency-Logs protokolliert und erleichtern die Aufklärung durch Angreifer.

### Behebung

- Den öffentlich zugänglichen Hostnamen des IdP explizit konfigurieren.
- Sicherstellen, dass alle Endpunkt-URLs den öffentlichen Hostnamen verwenden, keine internen Container- oder Dienstnamen.
- Keycloak: `KC_HOSTNAME` auf den öffentlichen externen Hostnamen setzen.

---

## oidc-endpoint-https | OIDC-Endpunkt Verwendet Kein HTTPS | HIGH

Einer oder mehrere OIDC-Endpunkte (Authorization, Token, JWKS, UserInfo) werden über HTTP bereitgestellt. Über HTTP übertragene Auth-Codes, Tokens und Benutzerdaten sind für Netzwerkbeobachter sichtbar.

### Behebung

- Alle OIDC-Endpunkte müssen ausschließlich über TLS bereitgestellt werden.
- Den Webserver konfigurieren, HTTP mit einer permanenten 301-Weiterleitung auf HTTPS umzuleiten.
- HSTS aktivieren, um künftigen HTTP-Zugriff zu verhindern.

---

## oidc-wildcard-redirect | Wildcard redirect_uri Registriert | HIGH

Ein Wildcard-Muster in einer registrierten redirect_uri erlaubt die Zustellung von Autorisierungscodes an jede URL, die dem Muster entspricht. Ein Angreifer mit einer Subdomain auf derselben Domain kann Autorisierungscodes empfangen.

### Behebung

- Nur exakte, vollqualifizierte Redirect-URIs registrieren.
- Niemals Wildcard-Muster (`*`) in Redirect-URIs verwenden.
- Alle registrierten Clients auf Wildcard-Redirects prüfen.

---

## oidc-http-redirect | HTTP redirect_uri Registriert | HIGH

Eine Nicht-Localhost-Redirect-URI verwendet HTTP statt HTTPS. An HTTP-Endpunkte gelieferte Autorisierungscodes sind für Netzwerkbeobachter und Proxy-Protokolle sichtbar.

### Behebung

- Alle Redirect-URIs müssen HTTPS verwenden, außer für Localhost-Entwicklungs-URIs.
- Alle Client-Registrierungen aktualisieren, um HTTPS-Redirect-URIs zu verwenden.

---

## oidc-localhost-redirect | Localhost redirect_uri In Produktion | LOW

Eine Localhost-Redirect-URI ist auf einem Produktions-IdP registriert. Obwohl für native Desktop-Anwendungen gültig, sind Localhost-URIs in Produktionskonfigurationen oft vergessene Entwicklungsartefakte aus Tests.

### Behebung

- Localhost-Redirect-URIs aus Produktions-Client-Registrierungen entfernen.
- Separate Entwicklungs-Client-Registrierungen mit Localhost-URIs verwenden.

---

## oidc-ip-redirect | IP-Adresse redirect_uri Registriert | MEDIUM

Eine Redirect-URI verwendet eine rohe IP-Adresse statt eines Hostnamens. IP-basierte Redirect-URIs umgehen hostnamen-basierte Sicherheitskontrollen, sind schwerer zu auditieren und können auf eine fehlkonfigurierte oder veraltete Entwicklungsregistrierung in Produktion hindeuten.

### Behebung

- Hostnamen-basierte Redirect-URIs verwenden.
- IP-Adressen in allen Client-Registrierungen durch DNS-Namen ersetzen.

---

## oidc-par | Pushed Authorization Requests (PAR) Nicht Unterstützt | INFO

PAR (RFC 9126) verschiebt Autorisierungsparameter vom Front-Channel (URL) in eine Back-Channel-Server-zu-Server-Anfrage, bevor der Benutzer weitergeleitet wird. Dies verhindert Parametermissbrauch und reduziert Token-Exposition in Browser-URLs.

### Behebung

- PAR für hochsichere Autorisierungsflows in Betracht ziehen.
- PAR für vertrauliche Clients mit sensiblen Daten erfordern.

---

## oidc-token-endpoint-auth-none | Token-Endpunkt Erlaubt Nicht-Authentifizierte Clients | MEDIUM

Der Token-Endpunkt bewirbt `none` als unterstützte Client-Authentifizierungsmethode. Dies erlaubt öffentlichen Clients, Autorisierungscodes ohne jede Client-Authentifizierung einzutauschen, was Authorization-Code-Abfangeangriffe ermöglicht, wenn PKCE nicht erzwungen wird.

### Behebung

- PKCE für alle öffentlichen Clients erfordern, die `none`-Authentifizierung verwenden.
- Für vertrauliche Clients `client_secret_basic` oder `private_key_jwt` erfordern.
- `none`-Auth für Clients, die sensible Scopes handhaben, niemals erlauben.

---

## oidc-jar | JWT Secured Authorization Requests (JAR) Nicht Unterstützt | INFO

JAR (RFC 9101) erlaubt die Übertragung von Autorisierungsanfrageparametern als signiertes JWT und verhindert so Parametermissbrauch im Front-Channel. Fehlt diese Funktion, können Autorisierungsparameter von einem Netzwerkangreifer auf dem Übertragungsweg modifiziert werden.

### Behebung

- JAR-Unterstützung aktivieren und signierte Request-Objekte für hochsichere Clients erfordern.
- Mit PAR für maximalen Front-Channel-Schutz kombinieren.

---

## oidc-revocation | Token-Revocation-Endpunkt Fehlt | LOW

Kein Token-Revocation-Endpunkt (RFC 7009) wird beworben. Ohne Revocation-Unterstützung bleiben kompromittierte Tokens bis zum Ablauf gültig. Logout-Flows, die sich auf Revocation verlassen, schlagen stillschweigend fehl.

### Behebung

- Einen Token-Revocation-Endpunkt implementieren und bewerben.
- Sicherstellen, dass Logout-Flows den Revocation-Endpunkt für alle aktiven Tokens aufrufen.
- Kurze Token-Lebenszeiten als kompensierende Maßnahme verwenden.

---

## oidc-request-uri-ssrf | request_uri-Parameter Ohne Allowlisting Unterstützt | MEDIUM

Wenn `request_uri_parameter_supported: true` ohne eine strikte Allowlist erlaubter URIs gesetzt ist, ruft der IdP Autorisierungsanfrageobjekte von beliebigen, vom Client angegebenen URLs ab. Dies erzeugt einen Server-Side-Request-Forgery-Vektor (SSRF) über den Autorisierungsendpunkt.

### Behebung

- Eine strikte Allowlist erlaubter request_uri-Werte pro Client-Registrierung implementieren.
- Anfragen an interne IP-Bereiche und Metadaten-Endpunkte blockieren.
- request_uri-Unterstützung deaktivieren, wenn JAR via direktes Request-Objekt ausreicht.

---

## oidc-multi-domain | OIDC-Endpunkte Überspannen Mehrere Domains | LOW

Die OIDC-Endpunkte (Issuer, Authorization, Token, JWKS, UserInfo) referenzieren mehr als zwei unterschiedliche Hostnamen. Dies deutet auf ein komplexes oder fragmentiertes Deployment hin, bei dem Vertrauensgrenzen unklar sind und Federation-Partner Schwierigkeiten bei der Validierung von Endpunkten haben können.

### Behebung

- OIDC-Endpunkte wenn möglich unter einer einzigen Domain konsolidieren.
- Jede legitime Cross-Domain-Endpunktverteilung dokumentieren und rechtfertigen.

---

## oidc-response-types-ok | Impliziter und Hybrid-Flow nicht beworben | INFO

Keine impliziten oder hybriden OAuth2-Response-Typen wurden in `response_types_supported` gefunden. Nur Authorization-Code-basierte Flows sind verfügbar, was dem sicheren Standard entspricht und das Risiko von Token-Lecks über URL-Fragmente minimiert.

### Behebung

- Kein Handlungsbedarf.

---

## oidc-ropc-ok | ROPC (Password)-Grant nicht beworben | INFO

Der Resource-Owner-Password-Credentials-Grant ist nicht in `grant_types_supported` gelistet. Damit ist das Risiko von Credential-Harvesting-Angriffen über direkte Passwort-Übergabe reduziert und MFA sowie Conditional-Access-Richtlinien bleiben wirksam.

### Behebung

- Kein Handlungsbedarf.

---

## oidc-device-flow-ok | Device-Authorization-Grant nicht beworben | INFO

Der Device-Flow-Grant ist nicht in `grant_types_supported` gelistet. Damit ist die Angriffsfläche für Device-Code-Phishing-Angriffe reduziert, bei denen Angreifer Benutzer dazu bringen, angreifer-kontrollierte Gerätesitzungen zu autorisieren.

### Behebung

- Kein Handlungsbedarf.

---

## oidc-implicit-grant-ok | Implicit-Grant nicht explizit gelistet | INFO

Der veraltete Implicit-Grant ist nicht in `grant_types_supported` gelistet. Damit ist das Risiko von Token-Lecks über URL-Fragmente und den Browser-Verlauf durch diesen veralteten Flow reduziert.

### Behebung

- Kein Handlungsbedarf.

---

## oidc-fragment-mode-ok | Fragment-Response-Modus nicht beworben | INFO

Der Fragment-Response-Modus ist nicht in `response_modes_supported` gelistet. Tokens und Codes werden nicht über URL-Hash-Fragmente übertragen, wodurch das Risiko von Browser-Verlaufs- und Referrer-Lecks über diesen Kanal entfällt.

### Behebung

- Kein Handlungsbedarf.

---

## oidc-alg-ok | Keine schwachen Signaturalgorithmen beworben | INFO

Alle in `id_token_signing_alg_values_supported` gelisteten Algorithmen gelten als sicher. Keine veralteten oder symmetrischen Algorithmen (`alg:none`, HS256/384/512, RS1) wurden gefunden.

### Behebung

- Kein Handlungsbedarf.

---

## oidc-pkce-s256 | PKCE mit S256 Code-Challenge-Methode unterstützt | INFO

Der Server bewirbt S256 als unterstützte PKCE Code-Challenge-Methode. S256 bindet den Autorisierungscode an einen kryptografischen Hash des Code-Verifiers und schützt so vor Authorization-Code-Abfangangriffen.

### Behebung

- Kein Handlungsbedarf. Sicherstellen, dass Clients so konfiguriert sind, dass PKCE erzwungen wird.

---

## oidc-endpoint-https-ok | Alle OIDC-Endpunkte und Issuer verwenden HTTPS | INFO

Alle beworbenen OIDC-Endpunkte (Authorization, Token, JWKS, UserInfo) sowie der Issuer-URI verwenden HTTPS. Tokens und Autorisierungscodes sind damit vor Abfangangriffen während der Übertragung geschützt.

### Behebung

- Kein Handlungsbedarf.

---

## oidc-pro-pkce-s256-ok | PKCE S256 unterstützt | INFO

Der IdP bewirbt S256 als unterstützte PKCE Code-Challenge-Methode. S256 hasht den Code-Verifier mit SHA-256, bevor er übertragen wird, sodass er selbst bei Abfangung nicht für den Token-Austausch wiederverwendet werden kann.

### Behebung

- Kein Handlungsbedarf. Sicherstellen, dass alle öffentlichen Clients so konfiguriert sind, dass PKCE mit S256 erzwungen wird.

---

## oidc-par-ok | Pushed Authorization Requests (PAR) unterstützt | INFO

Der IdP bewirbt einen PAR-Endpunkt (RFC 9126). Autorisierungsparameter werden vom Browser-URL in eine Server-zu-Server-Back-Channel-Anfrage verschoben, bevor der Benutzer weitergeleitet wird. Dies verhindert Parametermissbrauch, Request-Fälschung und Exposition von Parametern im Browser-Verlauf oder Protokollen.

### Behebung

- Kein Handlungsbedarf. PAR für hochsichere Autorisierungsflows in Betracht ziehen.

---

## oidc-token-auth-ok | Token-Endpunkt erfordert Client-Authentifizierung | INFO

Der Token-Endpunkt bewirbt ausschließlich starke Client-Authentifizierungsmethoden (client_secret_basic, private_key_jwt oder mTLS). Die `none`-Methode fehlt - alle Clients müssen sich authentifizieren, bevor Tokens ausgestellt werden.

### Behebung

- Kein Handlungsbedarf.

---

## oidc-jwks-ok | JWKS enthält mehrere ausreichend große Signierschlüssel | INFO

Der JWKS-Endpunkt veröffentlicht zwei oder mehr Signierschlüssel. Mehrere Schlüssel ermöglichen eine unterbrechungsfreie Schlüsselrotation - ein neuer Schlüssel wird veröffentlicht, bevor der alte entfernt wird, ohne dass bereits ausgestellte Tokens ungültig werden.

### Behebung

- Kein Handlungsbedarf.

---

## oidc-issuer-ok | OIDC-Issuer ist konsistent und auf einer einzigen Domain | INFO

Der Issuer-Wert stimmt mit dem Host des Discovery-Dokuments überein, und alle OIDC-Endpunkte werden von einem konsistenten Satz von Domains bereitgestellt. Keine Multi-Tenant- oder Cross-Domain-Deployment-Muster wurden erkannt.

### Behebung

- Kein Handlungsbedarf.

---

## oidc-redirect-uris-ok | Alle registrierten Redirect-URIs sind HTTPS und exakt | INFO

Alle registrierten Redirect-URIs verwenden HTTPS mit exakten Hostnamen - keine Wildcards, HTTP-URIs, Localhost- oder IP-Adressen wurden gefunden. Dies verhindert Autorisierungscode-Abfangung über Open-Redirect oder Netzwerkbeobachtung.

### Behebung

- Kein Handlungsbedarf.

---

## oidc-discovery-clean | OIDC-Discovery-Dokument enthält keine internen Infrastrukturangaben | INFO

Das Discovery-Dokument wurde auf interne Hostnamen, RFC1918-IP-Adressen, Kubernetes-Dienst-DNS und umgebungsspezifische Referenzen (Staging, Dev, Test) geprüft. Keine wurden gefunden - das Dokument enthält ausschließlich öffentlich zugängliche URLs.

### Behebung

- Kein Handlungsbedarf.
