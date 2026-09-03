## csp-overview | CSP | 

Das CSP-Modul analysiert `Content-Security-Policy`- und `Content-Security-Policy-Report-Only`-Header, die von Authentifizierungsendpunkten zurückgegeben werden. Eine schwache oder fehlende CSP auf Auth-Seiten ermöglicht Cross-Site-Scripting-Angriffe, die Sitzungstoken oder Credentials stehlen können.

### Durchgeführte Prüfungen

- Report-Only-Modus: CSP vorhanden, aber nicht durchgesetzt
- `unsafe-inline` in `script-src`: erlaubt Inline-Script-Injektion
- `unsafe-eval` in `script-src`: erlaubt dynamische Code-Ausführung
- Wildcard-Quellen (`*`) in beliebigen Direktiven
- Fehlendes `frame-ancestors`: Lücke beim Clickjacking-Schutz
- Fehlendes `form-action`: unkontrollierte Formular-Einreichungsziele
- Fehlendes `base-uri`: Risiko durch Base-Tag-Injektion
- Fehlende `default-src`-Fallback-Direktive

---

## csp-report-only | CSP Im Report-Only-Modus | MEDIUM

`Content-Security-Policy-Report-Only` ist vorhanden, aber der Durchsetzungsmodus fehlt. Der Report-Only-Modus sammelt Verstöße, blockiert jedoch nichts. Er bietet keinen tatsächlichen XSS-Schutz.

### Behebung

- CSP vom Report-Only- in den Durchsetzungsmodus überführen.
- Report-Only nur während der initialen Einführung verwenden. Innerhalb eines definierten Zeitrahmens auf Durchsetzung umstellen.

---

## csp-unsafe-inline | CSP Erlaubt unsafe-inline Scripts | HIGH

`unsafe-inline` in script-src erlaubt die Ausführung von Inline-JavaScript und hebt den XSS-Schutz auf dieser Seite vollständig auf. Login-Seiten mit dieser Einstellung sind vollständig anfällig für injizierte Skripte, die Credentials stehlen.

### Behebung

- `unsafe-inline` aus script-src entfernen.
- Inline-Event-Handler und Script-Blöcke durch externe Skripte ersetzen.
- Für verbleibende legitime Inline-Skripte Nonces oder Hashes verwenden.

---

## csp-unsafe-eval | CSP Erlaubt unsafe-eval | MEDIUM

`unsafe-eval` erlaubt dynamische JavaScript-Ausführung über `eval()`, `Function()`, `setTimeout(string)` und ähnliche Konstrukte. Angreifer, die Daten in diese Aufrufstellen injizieren können, erzielen XSS trotz vorhandener CSP.

### Behebung

- `unsafe-eval` aus script-src entfernen.
- Code, der `eval()` oder `new Function()` verwendet, refaktorieren.

---

## csp-wildcard-src | CSP Verwendet Wildcard-Quelle | MEDIUM

Ein Wildcard (`*`) in script-src, style-src, frame-src oder connect-src erlaubt Ressourcen von beliebigen Origins und macht den Zweck der CSP für diesen Ressourcentyp zunichte.

### Behebung

- Wildcards durch explizite vertrauenswürdige Origins ersetzen.
- `default-src 'self'` als sichere Basis verwenden und nur notwendige externe Quellen explizit erlauben.

---

## csp-frame-ancestors | CSP Fehlendes frame-ancestors | MEDIUM

Die `frame-ancestors`-Direktive fehlt. Dies ist der moderne Ersatz für X-Frame-Options und verhindert das Einbetten der Login-Seite in Iframes für Clickjacking-Angriffe. In modernen Browsern hat CSP `frame-ancestors` Vorrang vor X-Frame-Options.

### Behebung

- Hinzufügen: `frame-ancestors 'none'` um jegliches Framing zu verhindern.
- `frame-ancestors 'self'` nur verwenden, wenn die Anwendung sich legitim selbst einbettet.

---

## csp-form-action | CSP Fehlendes form-action | LOW

Ohne `form-action` kann jedes Formular auf der Seite an eine beliebige URL senden. Kann ein Angreifer ein Formular injizieren oder Formularwege über XSS manipulieren, werden Credentials an die Angreifer-Infrastruktur gesendet.

### Behebung

- Hinzufügen: `form-action 'self'` um zu beschränken, wohin Formulare Daten senden können.

---

## csp-base-uri | CSP Fehlendes base-uri | LOW

Ohne `base-uri` kann ein Angreifer, der ein `<base>`-Tag injizieren kann, alle relativen URLs (Skript-Quellen, Formular-Aktionen, Links) auf einen angreifer-kontrollierten Origin umleiten.

### Behebung

- Hinzufügen: `base-uri 'self'` oder `base-uri 'none'` um Base-Tag-Injektion zu verhindern.

---

## csp-no-default | CSP Ohne default-src Fallback | MEDIUM

Die CSP-Richtlinie besitzt keine `default-src`-Direktive. Ressourcentypen, die nicht explizit in anderen Direktiven aufgeführt sind, fallen auf das Erlauben aller Quellen zurück. Dies erzeugt stille Abdeckungslücken für Ressourcentypen, die der Entwickler nicht bedacht hat.

### Behebung

- `default-src 'none'` oder `default-src 'self'` als sichere Basis hinzufügen.
- Nur die spezifischen Ressourcentypen explizit erlauben, die die Anwendung benötigt.
