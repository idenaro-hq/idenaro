## cookies-overview | Cookies | 

Das Cookies-Modul prüft Sitzungs- und Authentifizierungs-Cookies, die von Auth-Endpunkten zurückgegeben werden. Es validiert Sicherheitsattribute, die Session-Hijacking, Cross-Site-Request-Forgery und Token-Diebstahl via JavaScript oder Netzwerkabfang verhindern.

### Durchgeführte Prüfungen

- `Secure`-Flag: Cookie-Übertragung auf HTTPS beschränkt
- `HttpOnly`-Flag: Verhinderung des JavaScript-Zugriffs
- `SameSite`-Attribut: CSRF-Cross-Origin-Einreichungskontrolle
- `SameSite=None` ohne `Secure`: Credential-Exposition über HTTP
- Persistente Cookie-Ablaufzeit: übermäßig lange Sitzungsdauer
- Zu breiter `Domain`-Geltungsbereich über Subdomains hinweg
- Mehrere Sitzungs-Cookie-Indikatoren, die auf eine Fehlkonfiguration hindeuten

---

## cookies-secure | Sitzungs-Cookie Ohne Secure-Flag | HIGH

Ein Sitzungs- oder Authentifizierungs-Cookie wird ohne das `Secure`-Flag gesetzt. Es wird über HTTP-Verbindungen übertragen, wodurch der Sitzungstoken auf jedem Netzwerkpfad, über den HTTP erreichbar ist, abgefangen werden kann.

### Behebung

- Das `Secure`-Attribut auf allen Authentifizierungs- und Sitzungs-Cookies setzen.
- In Kombination mit HSTS sicherstellen, dass niemals HTTP-Verbindungen hergestellt werden.

---

## cookies-httponly | Sitzungs-Cookie Ohne HttpOnly-Flag | MEDIUM

Ein Sitzungs-Cookie ist per JavaScript (`document.cookie`) zugänglich. Jede XSS-Schwachstelle auf der Domain ermöglicht den direkten Diebstahl des Sitzungstokens ohne weitere Ausnutzung.

### Behebung

- `HttpOnly` auf allen Sitzungs- und Authentifizierungs-Cookies setzen.
- Hinweis: HttpOnly verhindert keine XSS, begrenzt aber deren Auswirkung.

---

## cookies-samesite | Cookie Ohne SameSite-Attribut | LOW

Ohne `SameSite` werden Cookies in Cross-Site-Anfragen einbezogen, was CSRF-Angriffe ermöglicht. Ein Angreifer kann auf einer bösartigen Seite eingebettete Anfragen nutzen, um authentifizierte zustandsverändernde Aktionen auszulösen.

### Behebung

- `SameSite=Strict` für Sitzungs-Cookies setzen, sofern keine Cross-Site-Navigation benötigt wird.
- `SameSite=Lax` verwenden, wenn Top-Level-GET-Navigation von externen Seiten den Cookie einbeziehen muss.
- `SameSite=None` niemals ohne das `Secure`-Flag verwenden.

---

## cookies-samesite-none | SameSite=None Ohne Secure-Flag | HIGH

`SameSite=None` erfordert das `Secure`-Flag. Ohne dieses wird der Cookie entweder von modernen Browsern abgelehnt (Funktionsproblem) oder unsicher über HTTP übertragen (Sicherheitsproblem).

### Behebung

- Das `Secure`-Flag zusammen mit `SameSite=None` hinzufügen.
- Überprüfen, ob `SameSite=None` tatsächlich für Cross-Site-Verwendung benötigt wird.

---

## cookies-persistent | Sitzungs-Cookie Mit Langer Persistenter Ablaufzeit | LOW

Ein Sitzungs-Cookie besitzt eine explizite Ablaufzeit von mehr als 24 Stunden. Persistente Sitzungs-Cookies überleben Browser-Neustarts und verlängern das Fenster für Session-Hijacking nach Gerätediebstahl oder gemeinsamer Nutzung.

### Behebung

- Sitzungsbezogene Cookies (kein Expires/Max-Age) für Authentifizierungssitzungen verwenden.
- Falls Persistenz aus UX-Gründen erforderlich ist, auf 8-24 Stunden begrenzen und ein Inaktivitäts-Timeout implementieren.

---

## cookies-broad-domain | Cookie Mit Zu Breitem Domain-Geltungsbereich | MEDIUM

Ein Sitzungs-Cookie besitzt einen Wildcard-Domain-Geltungsbereich, der alle Subdomains abdeckt. Eine Subdomain-Übernahme oder XSS-Schwachstelle auf einer beliebigen Subdomain ermöglicht den Diebstahl des Authentifizierungs-Cookies über die gesamte Domain.

### Behebung

- Authentifizierungs-Cookies auf den spezifischen Hostnamen beschränken, nicht auf eine Wildcard-Domain.
- Das `Domain`-Attribut nur setzen, wenn Cross-Subdomain-Zugriff ausdrücklich erforderlich ist.

---

## cookies-multiple | Mehrere Sitzungs-Cookies Erkannt | LOW

Es werden mehr als zwei unterschiedliche Sitzungs- oder Authentifizierungs-Cookie-Namen gesetzt. Dies deutet auf eine fragmentierte Sitzungsarchitektur hin, bei der das Sicherstellen korrekter Sicherheits-Flags für alle Cookies und deren vollständiges Löschen beim Logout erschwert wird.

### Behebung

- Auf einen einzigen Sitzungs-Cookie pro Anwendungskontext konsolidieren.
- Logout-Flows prüfen, um sicherzustellen, dass alle Sitzungs-Cookies serverseitig gelöscht werden.
