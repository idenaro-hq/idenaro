## chains-overview | Verkettete Befunde | 

Verkettete Befunde werden nach Abschluss aller Einzelmodulprüfungen vom Korrelationsmodul erzeugt. Sie identifizieren Kombinationen gleichzeitig auftretender Schwachstellen, die zusammen einen schwerwiegenderen Angriffspfad bilden als jeder Einzelbefund. Ein verketteter Befund signalisiert, dass ein Angreifer zwei oder mehr Schwachstellen zu einer realistischen Exploit-Sequenz verbinden kann.

### Durchgeführte Prüfungen

- Admin-Exposition kombiniert mit schwacher Session-Sicherheit (kein HttpOnly / kein Secure)
- Fehlendes MFA kombiniert mit einem exponierten Admin-Endpunkt
- Aktiver impliziter OAuth-Flow bei gleichzeitig schwacher Content-Security-Policy
- Fehlendes HSTS kombiniert mit unsicheren Cookie-Flags
- Open Redirect beim Logout kombiniert mit aktivem OIDC-Flow
- User-Enumeration-Möglichkeit kombiniert mit fehlendem MFA
- Exponierter SCIM-Endpunkt kombiniert mit schwachen Zugriffskontrollen
- CORS-Fehlkonfiguration kombiniert mit einer sensitiven nicht authentifizierten API
- Mehrere Debug- oder Admin-Endpunkte gleichzeitig exponiert

---

## chain-admin-session | Verkettung: Admin-Exposition + Schwache Session-Sicherheit | CRITICAL

Ein Admin-Panel ist öffentlich zugänglich *und* die Session-Sicherheitsmaßnahmen sind schwach (fehlende Secure/HttpOnly-Flags oder HSTS). Zusammen bilden diese einen direkten Weg zur administrativen Kompromittierung: Ein Angreifer, der einen Sitzungstoken über SSL-Stripping oder XSS abfängt, erhält sofortigen Admin-Zugang.

### Behebungspriorität

- Behandlung als koordinierte Behebung, nicht als zwei separate Probleme.
- Admin-Zugang zuerst auf VPN/internes Netzwerk einschränken (Minuten zur Umsetzung, maximale Wirkung).
- Secure + HttpOnly + SameSite=Strict zu allen Sitzungs-Cookies hinzufügen.
- HSTS aktivieren, um SSL-Stripping zu verhindern.

---

## chain-mfa-admin | Verkettung: Fehlendes MFA + Exponierter Admin-Endpunkt | CRITICAL

Es werden keine MFA-Indikatoren erkannt *und* ein administrativer Endpunkt ist öffentlich zugänglich. Ein einziges kompromittiertes Passwort - via Phishing, Credential Stuffing oder Datenleck - gewährt vollständigen administrativen Zugriff auf das Identitätssystem ohne weitere Hürde.

### Behebungspriorität

- Zugriff auf den Admin-Endpunkt sofort auf internes Netzwerk oder VPN einschränken.
- MFA für alle Benutzerkonten aktivieren, insbesondere für Administratoren.
- Beide Probleme müssen behoben werden - nur eines zu beheben lässt eine kritische Exposition bestehen.

---

## chain-implicit-csp | Verkettung: Impliziter Flow + Schwache CSP | HIGH

Der implizite OIDC-Flow ist aktiviert *und* die Login-Seite besitzt eine schwache oder fehlende Content Security Policy. Eine XSS-Schwachstelle auf der Login-Seite kann Access-Token stehlen, die über URL-Fragmente übertragen werden - eine Kombination, die Token-Diebstahl trivial einfach macht.

### Behebungspriorität

- Impliziten Flow deaktivieren und auf Authorization Code + PKCE migrieren.
- Eine strikte CSP mit Nonces implementieren, um XSS auf der Login-Seite zu verhindern.

---

## chain-hsts-cookies | Verkettung: Fehlendes HSTS + Unsichere Cookie-Flags | HIGH

HSTS fehlt *und* Sitzungs-Cookies besitzen kein Secure-Flag. Diese Kombination ermöglicht einen vollständigen SSL-Stripping-Angriff: Ein Angreifer auf dem Netzwerkpfad stuft HTTPS auf HTTP herunter, und Sitzungs-Cookies werden ohne jeglichen browserseitigen Schutz im Klartext übertragen.

### Behebungspriorität

- Das Secure-Flag zu allen Sitzungs-Cookies hinzufügen.
- HSTS mit einer langen max-age aktivieren, um künftige HTTP-Verbindungen zu verhindern.

---

## chain-redirect-oidc | Verkettung: Open Redirect + Aktiver OIDC-Flow | HIGH

Ein Open Redirect ist vorhanden *und* OIDC ist konfiguriert. Open Redirects in OIDC-Autorisierungsflows sind direkt ausnutzbar für den Diebstahl von Autorisierungscodes: Ein Angreifer erstellt eine Autorisierungs-URL mit dem Open Redirect als redirect_uri, und der Autorisierungscode wird an den Angreifer zugestellt.

### Behebungspriorität

- Alle Redirect-Parameter gegen eine strikte Allowlist validieren.
- Sicherstellen, dass der OIDC-Autorisierungsendpunkt redirect_uri ausschließlich gegen registrierte Werte validiert.

---

## chain-enum-mfa | Verkettung: User-Enumeration + Kein MFA | HIGH

User-Enumeration ist möglich *und* MFA fehlt. Aufgezählte Benutzernamen können direkt für Credential-Stuffing- oder Password-Spray-Angriffe eingesetzt werden, ohne dass MFA den Angriff verlangsamt oder die Auswirkungen begrenzt.

### Behebungspriorität

- User-Enumeration beheben, indem identische Antworten für gültige und ungültige Konten zurückgegeben werden.
- MFA für alle Konten aktivieren, um eine zweite Hürde hinzuzufügen, selbst wenn Passwörter kompromittiert sind.

---

## chain-scim-iac | Verkettung: SCIM Exponiert + Schwache Zugriffskontrollen | CRITICAL

Ein SCIM-Bereitstellungsendpunkt ist zugänglich *und* weitere Schwächen bei den Zugriffskontrollen sind vorhanden. SCIM bietet vollständigen CRUD-Zugriff auf Benutzeridentitäten. Kombiniert mit weiteren IAM-Schwachstellen kann ein Angreifer Benutzer aufzählen, Privilegien eskalieren und über bereitgestellte Konten dauerhaften Zugriff aufrechterhalten.

### Behebungspriorität

- SCIM-Zugriff sofort auf authentifizierte Bereitstellungssysteme beschränken.
- Begleitende Zugriffskontrollen-Befunde beheben, um den kombinierten Angriffspfad zu eliminieren.

---

## chain-cors-api | Verkettung: CORS-Fehlkonfiguration + Sensitive API | HIGH

CORS ist auf einem auth-sensitiven Endpunkt fehlkonfiguriert *und* sensible API-Endpunkte sind zugänglich. Jeder authentifizierte Benutzer, der eine bösartige Website besucht, kann seine Sitzung für Cross-Origin-Anfragen an die Auth-API nutzen, was CSRF-ähnliche Angriffe gegen das Identitätssystem ermöglicht.

### Behebungspriorität

- CORS-Richtlinie auf eine strikte Origin-Allowlist umstellen.
- Sicherstellen, dass alle Auth-API-Endpunkte zusätzlich zur Sitzungsauthentifizierung CSRF-Tokens erfordern.

---

## chain-multi-endpoints | Verkettung: Mehrere Debug/Admin-Endpunkte Exponiert | HIGH

Drei oder mehr sensitive Endpunkte sind gleichzeitig öffentlich zugänglich. Dies ist keine isolierte Fehlkonfiguration, sondern zeigt ein systemisches Fehlen von Deployment-Härtung an. Jeder exponierte Endpunkt liefert unterschiedliche Informationen oder Zugänge, die die Gesamtangriffsfläche vergrößern.

### Behebungspriorität

- Vollständige Prüfung aller exponierten Endpunkte über die vom Scanner gefundenen hinaus durchführen.
- Eine Default-Deny-Richtlinie auf der Reverse-Proxy-Ebene für alle Management-Pfade implementieren.
- Alle Admin-, Debug- und Monitoring-Endpunkte als Klasse auf interne Netzwerke beschränken.
