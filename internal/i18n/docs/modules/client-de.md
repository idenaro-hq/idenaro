## client-overview | Client-Anwendungs-Sicherheit |

Das Client-Modul bewertet die Sicherheit der Relying-Party-Anwendung, die den Identity Provider nutzt. Es prüft Token-Validierung, Session-Cookie-Konfiguration, CORS-Richtlinien, CSRF-Schutz und Open-Redirect-Schwachstellen auf OAuth/OIDC-Callback-Endpunkten.

### Durchgeführte Prüfungen

- JWT-Signaturvalidierung: alg:none und abgelaufene Token werden als Bearer-Header gesendet
- Session-Cookie-Flags: Secure, HttpOnly und SameSite auf Authentifizierungsseiten
- CORS-Konfiguration auf API-Endpunkten der Anwendung
- OAuth-State-Parameter-Validierung auf Callback-Endpunkten
- Open-Redirect via redirect_uri-Injektion auf Callback-Endpunkten

---

## client-no-endpoint | Kein geschützter Endpunkt für Token-Probing gefunden | INFO

Keiner der gängigen geschützten Pfade hat mit HTTP 401 oder 403 geantwortet. Die Token-Validierungsprüfungen wurden übersprungen, da kein geeigneter Endpunkt zur Auswertung des Authorization-Headers gefunden wurde. Dies tritt häufig auf, wenn die Anwendung Cookie-basierte Sessions statt Bearer-Token verwendet, oder wenn der geschützte Pfad von den Standard-Kandidaten abweicht.

### Behebung

- Den geschützten Pfad der Anwendung direkt als Scan-Ziel übergeben, z. B. `https://app.example.com/oauth2/auth`, um gezielte Token-Validierungsprüfungen zu ermöglichen.

---

## client-endpoint-found | Geschützter Endpunkt identifiziert - Token-Probes aktiv | INFO

Ein mit HTTP 401 gesicherter Endpunkt wurde gefunden. alg:none- und Ablauf-Probes wurden gegen diesen Endpunkt gesendet, um die Token-Validierung der Anwendung zu prüfen.

---

## client-alg-none-inconclusive | alg:none-Probe nicht eindeutig - Antwort entspricht unauthentifiziertem Baseline | INFO

Der Endpunkt hat auf ein alg:none-JWT mit demselben HTTP-Statuscode wie auf eine Anfrage ohne Authorization-Header geantwortet. Das deutet darauf hin, dass der Authorization-Header ignoriert wird - z. B. weil die Anwendung Cookie-basierte Sessions oder einen Reverse-Proxy-Auth-Subrequest verwendet. Die JWT-Signaturvalidierung kann durch Probing allein nicht bestätigt werden.

---

## client-alg-none-enforced | Token-Signaturen werden erzwungen - alg:none-JWT abgelehnt | INFO

Der Endpunkt hat ein alg:none-JWT mit HTTP 401 abgelehnt, während der unauthentifizierte Baseline einen anderen Statuscode zurückgegeben hat. Dies bestätigt, dass die Anwendung den JWT ausgewertet und das unsignierte Token korrekt abgelehnt hat.

---

## client-expired-token-inconclusive | Abgelaufener-JWT-Probe nicht eindeutig - Antwort entspricht unauthentifiziertem Baseline | INFO

Der Endpunkt hat auf ein abgelaufenes JWT mit demselben HTTP-Statuscode wie auf eine Anfrage ohne Authorization-Header geantwortet. Das deutet darauf hin, dass der Authorization-Header ignoriert wird. Die Token-Ablaufvalidierung kann durch Probing allein nicht bestätigt werden.

---

## client-expired-token-enforced | Token-Ablauf wird erzwungen - abgelaufener JWT abgelehnt | INFO

Der Endpunkt hat ein abgelaufenes JWT (exp=2000-01-01) mit HTTP 401 abgelehnt, während der unauthentifizierte Baseline einen anderen Statuscode zurückgegeben hat. Dies bestätigt, dass die Anwendung die Token-Ablaufvalidierung korrekt durchführt.

---

## client-expired-token-accepted | Abgelaufener JWT von Relying Party akzeptiert | HIGH

Die Anwendung hat ein JWT akzeptiert, dessen exp-Anspruch auf 2000-01-01T01:00:00Z gesetzt war. Wenn die Token-Ablaufvalidierung nicht erzwungen wird, bleiben gestohlene oder geleakte Token dauerhaft gültig - unabhängig davon, wann sie ausgestellt wurden.

### Behebung

- Den exp-Anspruch bei jeder eingehenden Token-Anfrage validieren.
- Jedes Token ablehnen, dessen exp-Zeitstempel in der Vergangenheit liegt - unabhängig von anderen Ansprüchen.
- Sicherstellen, dass die Token-Validierungsbibliothek Ablaufprüfungen standardmäßig aktiviert hat.

---

## client-cors-absent | Keine CORS-Richtlinie auf Relying-Party-Endpunkt | INFO

Der Endpunkt hat keinen Access-Control-Allow-Origin-Header zurückgegeben. Cross-Origin-Anfragen werden vom Browser standardmäßig blockiert. Dieser Zustand gilt als konform, sofern keine Cross-Origin-Zugriffe aus vertrauenswürdigen Domains erforderlich sind.

---

## client-cors-allowed | CORS-Richtlinie vorhanden - Origin in Allowlist | INFO

Der Endpunkt gibt einen spezifischen Access-Control-Allow-Origin-Wert zurück, der den injizierten Angreifer-Origin nicht widerspiegelt. Die CORS-Konfiguration erscheint restriktiv und korrekt konfiguriert.

---

## client-no-cookies | Keine Session-Cookies auf Auth-Seiten beobachtet | INFO

GET-Anfragen auf gängige Authentifizierungsseiten haben keine Set-Cookie-Header zurückgegeben. Dies ist zu erwarten, wenn die Anwendung Cookies erst nach einem vollständigen POST/Redirect-Login-Flow setzt - GET-Probing allein kann die Cookie-Flags in diesem Fall nicht verifizieren.

---

## client-state-missing | OAuth-Callback akzeptiert Anfrage ohne State-Parameter | MEDIUM

Der Callback-Endpunkt hat eine Anfrage ohne State-Parameter mit einem anderen Statuscode als HTTP 400 beantwortet. Eine korrekte OAuth-Implementierung muss einen kryptografisch zufälligen State-Wert auf jeder Callback-Anfrage validieren, um CSRF-basierte Autorisierungscode-Injektion zu verhindern.

### Behebung

- Einen kryptografisch zufälligen State-Parameter auf jeder OAuth-Callback-Anfrage validieren.
- HTTP 400 zurückgeben, wenn der State-Parameter fehlt oder nicht mit dem erwarteten Wert übereinstimmt.
- Sicherstellen, dass der State-Wert serverseitig gespeichert und pro Anfrage überprüft wird.

---

## client-state-enforced | OAuth-State-Parameter auf Callback-Endpunkten erzwungen | INFO

Alle erreichbaren OAuth-Callback-Endpunkte haben Anfragen ohne State-Parameter mit HTTP 400 abgelehnt. Dies bestätigt, dass der CSRF-Schutz über State-Parameter aktiv ist.
