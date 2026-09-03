## tokens-overview | Token-Lecks | 

Das Token-Leck-Modul ruft JavaScript-Dateien ab, die von Authentifizierungsseiten geladen werden, und analysiert sie auf eingebettete Credentials und unsichere Client-seitige Token-Speichermuster. In JavaScript exponierte Tokens sind für jedes Skript auf der Seite und für jeden mit Zugriff auf den Quellcode lesbar.

### Durchgeführte Prüfungen

- Fest eingebettete Access-Tokens im JavaScript-Quellcode
- In JavaScript eingebettete OAuth-Client-Geheimnisse
- In `localStorage` gespeicherte Authentifizierungstoken
- In `sessionStorage` gespeicherte Authentifizierungstoken
- Authentifizierungstoken auf dem globalen `window`-Objekt
- OAuth-`client_id`-Werte in JavaScript (informativ)
- In JavaScript-Quellcode eingebettete API-Schlüssel

---

## tokens-access-token | Access-Token Im JavaScript Fest Eingebettet | CRITICAL

Ein Access-Token-Wert ist fest im JavaScript-Quellcode eingebettet. Access-Tokens gewähren API-Zugriff im Namen eines Benutzers oder Dienstes. Jeder Besucher kann diesen Token extrahieren und für authentifizierte API-Aufrufe verwenden, bis der Token abläuft oder widerrufen wird.

### Behebung

- Token sofort aus dem Quellcode entfernen.
- Token rotieren, um alle Kopien zu invalidieren.
- Backend-for-Frontend (BFF)-Muster verwenden, bei dem Tokens serverseitig gehalten werden.

---

## tokens-client-secret | OAuth-Client-Geheimnis Im JavaScript Exponiert | CRITICAL

Ein OAuth-Client-Geheimnis ist im JavaScript-Quellcode vorhanden. Client-Geheimnisse sind Credentials, die den OAuth-Client beim Autorisierungsserver authentifizieren. Jeder Besucher kann dieses Geheimnis nutzen, um die Anwendung zu imitieren, Tokens zu erlangen und authentifizierte API-Aufrufe zu tätigen.

### Behebung

- Exponiertes Client-Geheimnis sofort widerrufen und ein neues generieren.
- Client-Geheimnisse dürfen niemals in Frontend-Code erscheinen - BFF-Muster verwenden.
- Für SPAs, die kein Geheimnis bewahren können, ausschließlich öffentliche Clients mit PKCE verwenden (kein Client-Geheimnis).

---

## tokens-localstorage | Auth-Token In localStorage Gespeichert | HIGH

Authentifizierungstoken werden in `localStorage` gespeichert, das für jedes JavaScript auf der Seite zugänglich ist. Jede XSS-Schwachstelle ermöglicht vollständigen Token-Diebstahl. Anders als HttpOnly-Cookies bietet localStorage keinen XSS-Schutz.

### Behebung

- Tokens in HttpOnly-Cookies für server-gerenderte Apps speichern.
- Für SPAs: In-Memory-Speicherung mit Silent-Refresh via BFF verwenden.
- Falls localStorage verwendet werden muss, strikte CSP sicherstellen, um XSS zu verhindern.

---

## tokens-sessionstorage | Auth-Token In sessionStorage Gespeichert | MEDIUM

Authentifizierungstoken werden in `sessionStorage` gespeichert. Obwohl sessionStorage beim Schließen des Tabs geleert wird, ist sie für JavaScript zugänglich und anfällig für XSS-basierten Diebstahl.

### Behebung

- HttpOnly-Cookies gegenüber sessionStorage für die Token-Speicherung bevorzugen.
- Falls sessionStorage verwendet wird, strikte CSP implementieren, um XSS-Risiko zu mindern.

---

## tokens-window-global | Auth-Token Auf Globalem window-Objekt | HIGH

Ein Authentifizierungstoken ist dem globalen `window`-Objekt zugewiesen (z. B. `window.access_token`). Globale Variablen sind für jedes auf der Seite laufende Skript zugänglich, einschließlich Drittanbieter-Skripten, Browser-Erweiterungen und injiziertem Code.

### Behebung

- Closures oder Modul-Scope verwenden, um die Token-Sichtbarkeit einzuschränken.
- Tokens niemals globalen Variablen zuweisen.

---

## tokens-client-id | OAuth client_id Im JavaScript | INFO

Eine OAuth-`client_id` ist in JavaScript vorhanden. Für öffentliche Clients (SPAs, mobile Apps) ist dies erwartet und keine Schwachstelle - `client_id` ist kein Geheimnis. Überprüfen Sie jedoch, dass der Client als öffentlicher Client ohne Client-Geheimnis registriert ist und PKCE erzwungen wird.

### Was zu verifizieren ist

- Bestätigen, dass der Client als öffentlicher Client konfiguriert ist (kein Client-Geheimnis).
- Verifizieren, dass PKCE für diesen Client erforderlich ist.
- Sicherstellen, dass der Client minimale Scopes besitzt.

---

## tokens-api-key | API-Schlüssel Im JavaScript Exponiert | MEDIUM

Ein API-Schlüssel ist im JavaScript-Quellcode vorhanden. API-Schlüssel im Frontend-JS sind für alle Benutzer der Anwendung sichtbar. Abhängig von der API kann dies Quota-Missbrauch, unauthentifizierten Datenzugriff oder weitere Aufklärung ermöglichen.

### Behebung

- API-Aufrufe durch einen Backend-Server proxyen, der den API-Schlüssel serverseitig hält.
- Exponierten API-Schlüssel rotieren.
- Falls von der API unterstützt, Schlüssel nach Domain oder IP einschränken.
