## headers-overview | Sicherheits-Header | 

Das Sicherheits-Header-Modul ruft HTTP-Antworten von Authentifizierungsendpunkten ab und validiert das Vorhandensein und die Konfiguration von Browser-Sicherheitsheadern. Diese Header bilden eine kritische Defense-in-Depth-Schicht um die Authentifizierungsoberfläche.

### Durchgeführte Prüfungen

- HTTP Strict Transport Security (HSTS): Vorhandensein und max-age-Wert
- Content-Security-Policy: Vorhandensein (detaillierte Analyse durch das CSP-Modul)
- X-Frame-Options: Clickjacking-Schutz
- X-Content-Type-Options: Verhinderung von MIME-Sniffing
- Referrer-Policy: Kontrolle von Referrer-Lecks
- Permissions-Policy: Einschränkungen des Browser-Feature-Zugriffs
- Subresource Integrity (SRI) bei extern geladenen Skripten
- Cross-Origin-Opener-Policy (COOP): Cross-Origin-Isolation
- Server- und Technologieversionsdisclosure in Antwortheadern

---

## headers-hsts | Fehlendes HSTS | HIGH

Ohne HTTP Strict Transport Security folgen Browser HTTP-Weiterleitungen und Benutzer sind anfällig für SSL-Stripping-Angriffe, die HTTPS-Verbindungen auf HTTP herabstufen und Traffic-Abfang ermöglichen.

### Behebung

- Hinzufügen: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- Mit einem kurzen max-age (300s) beginnen und nach Bestätigung der korrekten HTTPS-Funktion erhöhen.
- Zur HSTS-Preload-Liste auf hstspreload.org einreichen, um Browser-seitige Durchsetzung zu erhalten.

---

## headers-csp | Fehlende Oder Schwache Content-Security-Policy | MEDIUM

Ohne CSP läuft injiziertes JavaScript mit vollen Seitenrechten. Auf Login-Portalen können injizierte Skripte Credentials ernten und Sitzungstoken stehlen. `unsafe-inline` in script-src hebt praktisch jeden XSS-Schutz auf.

### Behebung

- Einstieg mit: `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'`
- Nonces oder Hashes statt `unsafe-inline` verwenden.
- Zunächst im Report-Only-Modus einsetzen, um Verstöße zu identifizieren, bevor durchgesetzt wird.

---

## headers-xframe | Fehlendes X-Frame-Options | MEDIUM

Ohne Frame-Schutz können Login-Seiten in Iframes auf angreifer-kontrollierten Seiten eingebettet werden. Clickjacking-Angriffe überlagern transparente Iframes, um Credentials abzufangen oder authentifizierte Aktionen ohne Wissen des Benutzers auszulösen.

### Behebung

- Hinzufügen: `X-Frame-Options: DENY`
- Oder CSP verwenden: `frame-ancestors 'none'`, das in modernen Browsern Vorrang hat.

---

## headers-xcto | Fehlendes X-Content-Type-Options | LOW

Ohne `nosniff` können Browser Antworten unabhängig vom deklarierten Content-Type MIME-sniffing unterziehen. Ein Angreifer, der Dateien auf den Server hochladen kann, kann diese durch MIME-Sniffing als Skripte ausführen lassen.

### Behebung

- Hinzufügen: `X-Content-Type-Options: nosniff`

---

## headers-referrer | Fehlende Referrer-Policy | LOW

Ohne eine Referrer-Policy können Authentifizierungstoken oder Session-IDs in URLs über den Referer-Header an Drittressourcen auf Auth-Seiten geleakt werden (Analytics, Fonts, CDNs).

### Behebung

- Hinzufügen: `Referrer-Policy: strict-origin-when-cross-origin` oder `no-referrer`

---

## headers-permissions | Fehlende Permissions-Policy | INFO

Die Permissions-Policy schränkt den Browser-Feature-Zugriff ein (Kamera, Mikrofon, Geolokalisierung). Auf Identity-Portalen reduziert sie die Angriffsfläche, die jedem injizierten Skript oder bösartigen Iframe zur Verfügung steht.

### Behebung

- Hinzufügen: `Permissions-Policy: geolocation=(), camera=(), microphone=()`

---

## headers-sri | Subresource Integrity (SRI) Fehlt Bei CDN-Skripten | MEDIUM

Extern von CDNs geladene Skripte ohne SRI-Hashes werden auch dann ausgeführt, wenn das CDN kompromittiert ist und bösartige Inhalte bereitstellt. Auf Login-Seiten erzeugt dies einen Supply-Chain-Angriffsvektor für Credential-Diebstahl.

### Behebung

- `integrity`- und `crossorigin`-Attribute zu allen externen Script- und Link-Tags hinzufügen.
- Hashes generieren mit: `openssl dgst -sha384 -binary script.js | openssl base64 -A`
- Kritische Skripte selbst hosten erwägen, um CDN-Abhängigkeit zu eliminieren.

---

## headers-coop | Cross-Origin-Opener-Policy Fehlt | LOW

Ohne COOP behalten von der eigenen Seite geöffnete Seiten einen Browsing-Context-Group mit dem Opener. Dies ermöglicht Cross-Origin-Seiten den Zugriff auf das `window`-Objekt der Login-Seite und die Ausführung von Timing-Angriffen oder XS-Leaks.

### Behebung

- Hinzufügen: `Cross-Origin-Opener-Policy: same-origin`

---

## headers-info-disclosure | Server/Technologieversion Disclosure | LOW

Antwortheader (Server, X-Powered-By, X-AspNet-Version, X-Generator) enthüllen die Webserver-Software und Version. Dies erleichtert gezielte Ausnutzung, da Angreifer bekannte CVEs für die spezifische Version nachschlagen können.

### Behebung

- Server-Header unterdrücken: Nginx: `server_tokens off;`, Apache: `ServerTokens Prod`
- X-Powered-By in der Anwendungskonfiguration entfernen.
- In ASP.NET: `<httpRuntime enableVersionHeader="false"/>`

---

## headers-hsts-ok | Strict-Transport-Security (HSTS) korrekt konfiguriert | INFO

Der Strict-Transport-Security-Header ist vorhanden und korrekt konfiguriert. Browser erzwingen HTTPS für die beworbene max-age-Dauer, wodurch SSL-Stripping-Angriffe verhindert werden.

### Behebung

- Kein Handlungsbedarf.

---

## headers-csp-ok | Content-Security-Policy (CSP) korrekt konfiguriert | INFO

Der Content-Security-Policy-Header ist vorhanden und enthält kein `unsafe-inline` in `script-src`. Injizierte Skripte werden durch die aktive CSP blockiert.

### Behebung

- Kein Handlungsbedarf.

---

## headers-xframe-ok | X-Frame-Options korrekt konfiguriert | INFO

Der X-Frame-Options-Header ist vorhanden. Die Seite kann nicht in fremde Iframes eingebettet werden, wodurch Clickjacking-Angriffe auf Login-Formulare verhindert werden.

### Behebung

- Kein Handlungsbedarf.

---

## headers-xcto-ok | X-Content-Type-Options korrekt konfiguriert | INFO

Der X-Content-Type-Options-Header ist vorhanden. Browser führen kein MIME-Sniffing durch, wodurch das Risiko der unbeabsichtigten Skriptausführung hochgeladener Dateien eliminiert wird.

### Behebung

- Kein Handlungsbedarf.

---

## headers-referrer-ok | Referrer-Policy korrekt konfiguriert | INFO

Der Referrer-Policy-Header ist vorhanden. Authentifizierungstoken oder Session-IDs in URLs werden nicht über den Referer-Header an Drittressourcen weitergegeben.

### Behebung

- Kein Handlungsbedarf.

---

## headers-permissions-ok | Permissions-Policy korrekt konfiguriert | INFO

Der Permissions-Policy-Header ist vorhanden. Der Browser-Feature-Zugriff ist eingeschränkt und reduziert die Angriffsfläche für injizierte Skripte auf dem Identity-Portal.

### Behebung

- Kein Handlungsbedarf.
