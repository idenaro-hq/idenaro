## tls-overview | TLS | 

Das TLS-Modul prüft die Transport-Layer-Security-Konfiguration von Authentifizierungsendpunkten. Es validiert den Zertifikatszustand, verhandelt TLS-Verbindungen zur Überprüfung der Protokollversion und Cipher-Suite-Stärke und prüft die HTTPS-Durchsetzung über die gesamte Authentifizierungsoberfläche.

### Durchgeführte Prüfungen

- Zertifikatsablauf: abgelaufen und innerhalb von 30 Tagen ablaufend
- Selbst-signierte Zertifikate, die von keiner öffentlichen CA vertraut werden
- Zertifikats-Hostname-Mismatch gegen das Ziel
- Interner Hostname in den Subject Alternative Names (SAN) des Zertifikats
- Veraltete TLS-Protokollversion ausgehandelt: SSLv3, TLS 1.0, TLS 1.1
- HTTP antwortet ohne Weiterleitung zu HTTPS
- Mixed Content (HTTP-Subressourcen) auf HTTPS-Auth-Seiten
- Schwache Cipher Suites: RC4, 3DES, Export-Grade
- Cipher Suites ohne Forward Secrecy (nicht ECDHE/DHE)
- OCSP-Stapling fehlt

---

## tls-expired | TLS-Zertifikat Abgelaufen | CRITICAL

Das TLS-Zertifikat ist abgelaufen. Browser zeigen Sicherheitswarnungen an und viele Clients verweigern die Verbindung vollständig. Benutzer, die Warnungen akzeptieren, gewöhnen sich daran, Zertifikatsfehler zu ignorieren, was die Sicherheitskultur schwächt. Dies muss sofort behoben werden.

### Behebung

- Zertifikat sofort erneuern.
- Let's Encrypt mit certbot und automatisierten Erneuerungshooks verwenden.
- Monitoring einrichten, das bei 30 und 7 Tagen vor Ablauf warnt.

---

## tls-expiring | TLS-Zertifikat Läuft Bald Ab | HIGH

Das TLS-Zertifikat läuft innerhalb von 30 Tagen ab. Unterlässt man die Erneuerung, kommt es zu Browser-Sicherheitswarnungen und Verbindungsfehlern für alle Clients, die die Zertifikatsgültigkeit erzwingen.

### Behebung

- Zertifikat vor Ablauf erneuern.
- Automatisierte Erneuerung implementieren (Let's Encrypt, ACME-Protokoll).

---

## tls-self-signed | Selbst-Signiertes Zertifikat | HIGH

Das Zertifikat ist selbst-signiert und wird standardmäßig von keinem Browser oder Betriebssystem vertraut. Benutzer sehen Sicherheitswarnungen und müssen diese manuell akzeptieren. Automatisierte Clients und Monitoring-Systeme scheitern bei der Verbindung. Selbst-signierte Zertifikate auf Produktions-Auth-Portalen zeigen fehlende Zertifikats-Management-Prozesse an.

### Behebung

- Durch ein Zertifikat einer vertrauenswürdigen CA ersetzen (Let's Encrypt, DigiCert, Sectigo).
- Für interne Dienste eine interne CA betreiben und den Root via MDM oder Gruppenrichtlinie verteilen.

---

## tls-hostname-mismatch | TLS-Zertifikat Hostname-Mismatch | HIGH

Das Zertifikat ist für den Ziel-Hostname nicht gültig. Dies deutet typischerweise auf einen falsch konfigurierten Reverse-Proxy hin, der ein internes Zertifikat auf einem öffentlichen Endpunkt bereitstellt, oder auf ein für den falschen Hostname ausgestelltes Zertifikat.

### Behebung

- Ein Zertifikat ausstellen, das den korrekten Hostname in den Subject Alternative Names enthält.
- Sicherstellen, dass die TLS-Terminierung des Reverse-Proxys mit dem richtigen Zertifikat konfiguriert ist.

---

## tls-internal-san | Interner Hostname Im TLS-Zertifikat SAN | MEDIUM

Das Zertifikat-SAN enthält interne Hostnamen (.internal, .local, .corp, Kubernetes-Dienstnamen). Diese werden dauerhaft in Certificate-Transparency-Logs protokolliert und enthüllen jedem, der CT-Logs durchsucht, dauerhaft die interne Netzwerktopologie.

### Behebung

- Separate Zertifikate für interne und externe Hostnamen ausstellen.
- Keine internen DNS-Namen in Zertifikaten aufnehmen, die auf öffentlichen Endpunkten verwendet werden.

---

## tls-deprecated-version | Veraltete TLS-Version Ausgehandelt | HIGH

Der Server hat TLS 1.0 oder 1.1 ausgehandelt, die veraltet und anfällig für POODLE-, BEAST- und Downgrade-Angriffe sind. Auth-Portale müssen mindestens TLS 1.2 verwenden, TLS 1.3 wird bevorzugt.

### Behebung

- TLS 1.0 und 1.1 in der Webserver-Konfiguration deaktivieren.
- Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`
- Apache: `SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1`

---

## tls-no-https-redirect | HTTP Antwortet Ohne HTTPS-Weiterleitung | HIGH

Der Server antwortet auf einfache HTTP-Anfragen ohne Weiterleitung zu HTTPS. Benutzer, die die HTTP-URL aufrufen, haben ihre Sitzungs-Credentials und Tokens im Klartext übertragen.

### Behebung

- Gesamten HTTP-Traffic mit einer permanenten 301-Weiterleitung zu HTTPS umleiten.
- In Kombination mit HSTS künftigen HTTP-Zugriff verhindern.

---

## tls-mixed-content | Mixed Content Auf Auth-Seite | MEDIUM

Die HTTPS-Login-Seite referenziert HTTP-Ressourcen (Skripte, Stylesheets, Bilder). Moderne Browser blockieren Mixed Content, was zu Funktionsproblemen führt. HTTP-Ressourcen auf einer HTTPS-Seite können von einem Netzwerkangreifer abgefangen und ersetzt werden.

### Behebung

- Alle HTTP-Ressourcenreferenzen durch HTTPS-Entsprechungen ersetzen.
- Protokoll-relative URLs oder absolute HTTPS-URLs für alle Ressourcen verwenden.
- Eine CSP-Direktive `upgrade-insecure-requests` als Fallback hinzufügen.

---

## tls-weak-cipher | Schwache Cipher Suite Ausgehandelt | HIGH

Der Server hat eine Cipher Suite mit RC4, 3DES oder einem anderen veralteten Algorithmus ausgehandelt. RC4 ist gebrochen und 3DES ist anfällig für den SWEET32-Birthday-Angriff. Diese Cipher Suites dürfen auf Authentifizierungsinfrastruktur nicht verwendet werden.

### Behebung

- Alle RC4-, 3DES- und NULL-Cipher-Suites deaktivieren.
- Eine moderne Cipher-Suite-Liste verwenden: ECDHE+AESGCM, ECDHE+CHACHA20.
- Mit ssl-labs.com testen und eine A+-Bewertung anstreben.

---

## tls-no-forward-secrecy | Cipher Suite Ohne Forward Secrecy | HIGH

Der Server hat eine Cipher Suite mit RSA-Schlüsselaustausch (kein Forward Secrecy) ausgehandelt. Wird der private Schlüssel des Servers jemals kompromittiert, können alle aufgezeichneten TLS-Sitzungen der Vergangenheit rückwirkend entschlüsselt werden.

### Behebung

- ECDHE-Cipher-Suites priorisieren, die Forward Secrecy bieten.
- RSA-Schlüsselaustausch-Cipher-Suites deaktivieren.

---

## tls-no-ocsp | OCSP-Stapling Fehlt | LOW

OCSP-Stapling ist nicht konfiguriert. Ohne dieses müssen Browser eine separate Echtzeit-Anfrage an den OCSP-Server der CA stellen, um den Zertifikats-Sperrstatus zu überprüfen. Dies erhöht die Latenz und erzeugt ein Datenschutzleck (die CA erfährt, welche Seiten der Benutzer besucht).

### Behebung

- Nginx: `ssl_stapling on; ssl_stapling_verify on;`
- Apache: `SSLUseStapling on`

---

## tls-version-ok | Sichere TLS-Version ausgehandelt | INFO

Der Server hat TLS 1.2 oder TLS 1.3 ausgehandelt, was die Mindestanforderung erfüllt oder übertrifft. Veraltete Protokollversionen (TLS 1.0, TLS 1.1) werden nicht akzeptiert.

### Behebung

- Kein Handlungsbedarf. TLS 1.3 gegenüber TLS 1.2 bevorzugen, wo möglich.

---

## tls-cert-ok | TLS-Zertifikat ist gültig und vertrauenswürdig | INFO

Das TLS-Zertifikat ist von einer vertrauenswürdigen CA ausgestellt, stimmt mit dem Hostnamen überein und hat noch ausreichend Gültigkeitsdauer. Keine Ablaufwarnungen, Selbstsignierung, Hostname-Mismatches oder unvollständige Zertifikatsketten wurden erkannt.

### Behebung

- Kein Handlungsbedarf. Automatisierte Zertifikatserneuerung sicherstellen.

---

## tls-https-redirect-ok | HTTP-zu-HTTPS-Weiterleitung ist aktiv | INFO

Der Server antwortet auf einfache HTTP-Anfragen mit einer Weiterleitung zu HTTPS. Benutzer, die die HTTP-URL aufrufen, werden automatisch auf eine verschlüsselte Verbindung umgeleitet.

### Behebung

- Kein Handlungsbedarf. HSTS in Betracht ziehen, um künftigen HTTP-Zugriff dauerhaft zu verhindern.
