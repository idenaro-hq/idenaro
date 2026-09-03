## redirects-overview | Weiterleitungen | 

Das Weiterleitungs-Modul prüft Login-, Logout- und OAuth-Callback-Endpunkte auf Open-Redirect-Schwachstellen und Debug-Informationslecks. Open Redirects auf Authentifizierungsoberflächen können mit Phishing-Angriffen verkettet oder zum Stehlen von OAuth-Autorisierungscodes genutzt werden.

### Durchgeführte Prüfungen

- Vorhandensein von Redirect-Parametern auf Login-Seiten (`next`, `return_to`, `redirect_uri` etc.)
- Open Redirect am Logout-Endpunkt: Off-Domain-Weiterleitung ohne Allowlisting akzeptiert
- Debug- oder Fehlerinformationen in OAuth-Callback- oder Redirect-Endpunkt-Antworten geleakt

---

## redirects-param | Redirect-Parameter Auf Login-Seite | MEDIUM

Die Login-Seite referenziert einen Redirect-Parameter (redirect=, returnUrl=, next= etc.). Wird dieser Parameter nicht gegen eine Allowlist validiert, ermöglicht er Open-Redirect-Angriffe. In Kombination mit OIDC-Flows werden Open Redirects zu Authorization-Code-Diebstahl-Vektoren.

### Behebung

- Alle Redirect-Parameter gegen eine strikte Allowlist registrierter URLs validieren.
- Jeden Wert, der nicht auf der Allowlist steht, ablehnen oder bereinigen.
- Niemals auf beliebige externe URLs basierend auf Benutzereingaben weiterleiten.

---

## redirects-open | Open Redirect Am Logout-Endpunkt | HIGH

Der Logout-Endpunkt hat auf eine über `post_logout_redirect_uri` injizierte angreifer-kontrollierte URL weitergeleitet. Nach legitimem Logout werden Benutzer auf eine überzeugende gefälschte Login-Seite geleitet, was Credential-Phishing ermöglicht.

### Behebung

- `post_logout_redirect_uri` gegen eine registrierte Allowlist validieren.
- Jede URI ablehnen, die nicht für den Client vorregistriert ist.
- Für OIDC: das `post_logout_redirect_uris`-Client-Metadaten-Feld verwenden.

---

## redirects-debug-leak | Debug-Informationen Am Callback-Endpunkt Geleakt | MEDIUM

Ein Callback- oder Redirect-Endpunkt hat beim Zugriff ohne gültigen Autorisierungskontext anscheinend einen Stack-Trace oder Debug-Output zurückgegeben. Dies enthüllt Implementierungsdetails, Framework-Versionen und interne Dateipfade, die für gezielte Angriffe nützlich sind.

### Behebung

- Debug-Ausgabe in der Produktion deaktivieren. Für alle Fehlerzustände generische Fehlerseiten zurückgeben.
- Sicherstellen, dass der Framework-Debug-Modus in Produktions-Deployments deaktiviert ist.
