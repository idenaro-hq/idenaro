## cors-overview | CORS | 

Das CORS-Modul testet Cross-Origin-Resource-Sharing-Richtlinien auf Authentifizierungs-, Token- und API-Endpunkten. Es sendet präparierte `Origin`-Header und analysiert `Access-Control-Allow-Origin`- und `Access-Control-Allow-Credentials`-Antwortheader auf gefährliche Konfigurationen.

### Durchgeführte Prüfungen

- Wildcard `Access-Control-Allow-Origin: *` auf Endpunkten, die Credentials verarbeiten
- Origin-Spiegelung: Server spiegelt den Anfrage-`Origin` bei gleichzeitiger Credential-Erlaubnis zurück
- Null-Origin-Akzeptanz kombiniert mit `Allow-Credentials: true`
- Preflight-Cache-Dauer: aggressive `Access-Control-Max-Age`-Werte

---

## cors-wildcard | Wildcard CORS auf Auth-Endpunkt | HIGH

`Access-Control-Allow-Origin: *` auf Token-, Benutzer- oder Sitzungsendpunkten erlaubt jeder Website, Cross-Origin-Anfragen zu stellen und die Antwort zu lesen. Dies ermöglicht Cross-Origin-Credential- und Token-Diebstahl von jeder bösartigen Website.

### Behebung

- Niemals Wildcard-CORS auf authentifizierten Endpunkten verwenden.
- Eine explizite Allowlist vertrauenswürdiger Origins serverseitig pflegen und validieren.

---

## cors-reflected | Gespiegelter CORS-Origin Mit Credentials | CRITICAL

Der Server spiegelt den Anfrage-Origin-Header in `Access-Control-Allow-Origin` zurück, kombiniert mit `Access-Control-Allow-Credentials: true`. Jede Website kann credentialbasierte Cross-Origin-Anfragen an diesen Endpunkt stellen und die Antwort lesen, was eine Kontoübernahme ermöglicht.

### Behebung

- Origin gegen eine strikte Allowlist validieren, bevor er gespiegelt wird.
- Niemals ein dynamisches/gespiegeltes ACAO mit `ACAC: true` kombinieren.

---

## cors-null-origin | Null-Origin Mit Credentials Akzeptiert | HIGH

Der Null-Origin wird mit Credentials akzeptiert. Der Null-Origin kann aus gekapselten Iframes, file://-Seiten und umgeleiteten Cross-Origin-Anfragen ausgelöst werden, was Credential-Diebstahl aus lokalen HTML-Dateien oder gekapselten Kontexten ermöglicht.

### Behebung

- Den Null-Origin in der CORS-Richtlinie niemals erlauben.
- Null-Origin-Anfragen in der serverseitigen CORS-Validierung explizit ablehnen.

---

## cors-max-age | CORS Preflight-Caching Zu Aggressiv | LOW

`Access-Control-Max-Age` ist auf mehr als 86400 Sekunden (24 Stunden) gesetzt. Erweitertes Preflight-Caching bedeutet, dass CORS-Richtlinienänderungen länger als einen Tag benötigen, um wirksam zu werden, was die Reaktion auf einen Vorfall verzögert, wenn eine Fehlkonfiguration entdeckt wird.

### Behebung

- `Access-Control-Max-Age` auf maximal 86400 (24 Stunden) setzen.
- Für sicherheitssensitive Endpunkte kürzere Cache-Dauern verwenden (z. B. 600 Sekunden).

---

## cors-restricted-ok | Keine permissive CORS-Richtlinie auf Auth-Endpunkten erkannt | INFO

Preflight-Anfragen mit angreifer-kontrollierten Origins (evil.com, attacker.example.com, null) wurden an gängige Auth- und API-Endpunkte gesendet. Keiner hat mit einem permissiven `Access-Control-Allow-Origin`-Header geantwortet. Cross-Origin-Token-Extraktion ist über diese Endpunkte nicht möglich.

### Behebung

- Kein Handlungsbedarf.
