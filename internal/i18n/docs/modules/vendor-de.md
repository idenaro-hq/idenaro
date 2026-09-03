## vendor-overview | Herstellerspezifisch | 

Das Herstellerspezifisch-Modul erkennt Identity-Platform-Hersteller-Signaturen aus HTTP-Antworten und testet deren Verwaltungsoberflächen und proprietäre Endpunkte auf nicht authentifizierten Zugriff. Jeder Hersteller exponiert einzigartige Admin- und API-Oberflächen über Standardprotokolle hinaus.

### Durchgeführte Prüfungen

- **Keycloak**: Admin-Konsole, dynamischer Client-Registrierungsendpunkt, Realm-Listen-API
- **ADFS**: IdP-initiierte Anmeldeseite, WS-Federation-passiver Endpunkt
- **PingFederate**: Zugänglichkeit der administrativen Konsole
- **Authentik**: Users-API-Endpunkt ohne Authentifizierung
- **Azure AD**: Legacy-Authentifizierungsendpunkt (`/common/oauth2/token`)

---

## vendor-keycloak-admin | Keycloak-Admin-Konsole Zugänglich | HIGH

Die Keycloak-Admin-Konsole ist aus dem öffentlichen Internet zugänglich. Die Admin-Konsole bietet vollständige Kontrolle über alle Realms, Clients, Benutzer, Identity-Provider und Authentifizierungsflows. Ein einziges kompromittiertes Admin-Konto gewährt vollständige IdP-Kontrolle.

### Behebung

- `--hostname-admin` verwenden, um die Admin-Konsole auf einem separaten internen Hostnamen bereitzustellen.
- Den `/admin`-Pfad am Reverse-Proxy für externe Anfragen blockieren.
- MFA für alle Admin-Konsolen-Authentifizierungen erfordern.

---

## vendor-keycloak-client-reg | Keycloak Dynamische Client-Registrierung Offen | HIGH

Der dynamische Keycloak-Client-Registrierungsendpunkt akzeptiert neue Client-Registrierungen ohne Initial-Access-Token. Jede nicht authentifizierte Partei kann OAuth-Clients in diesem Realm registrieren und potenziell Redirect-URIs für Authorization-Code-Diebstahl erlangen.

### Behebung

- Initial-Access-Token für alle Client-Registrierungen erfordern.
- Keycloak: Clients → Client Registration → „Client Registration Access Token Required" setzen.

---

## vendor-keycloak-realm-list | Keycloak Realm-Liste Zugänglich | INFO

Keycloak exponiert die Namen aller konfigurierten Realms über den `/realms/`-Endpunkt. Jeder Realm-Name ist eine separate Angriffsfläche mit eigener OIDC/SAML-Konfiguration, und das Kennen von Realm-Namen ermöglicht gezielte Enumeration weiterer Endpunkte.

### Behebung

- Dies ist erwartetes Keycloak-Verhalten. In der Produktion nicht offensichtliche Realm-Namen verwenden.
- Sicherstellen, dass jeder Realm einzeln gehärtet ist - der Master-Realm sollte öffentliche Client-Registrierung und Token-Zugriff einschränken.

---

## vendor-adfs-idp-initiated | ADFS IdP-Initiierte Anmeldeseite Exponiert | HIGH

Die ADFS-IdP-initiierte Anmeldeseite ist öffentlich zugänglich. Dieser Endpunkt wird häufig in Phishing-Kampagnen missbraucht, da er die Initiierung der Authentifizierung bei beliebigen Anwendungen ohne SP-Beteiligung ermöglicht, was SP-initiierte Flow-Kontrollen und einige Conditional-Access-Richtlinien umgeht.

### Behebung

- IdP-initiiertes SSO deaktivieren: `Set-AdfsProperties -EnableIdPInitiatedSignonPage $false`
- Falls für spezifische Anwendungen erforderlich, über Conditional-Access-Richtlinien einschränken.

---

## vendor-adfs-ws-fed | ADFS WS-Federation-Passiver Endpunkt Exponiert | HIGH

Der passive ADFS-WS-Federation-Endpunkt ist öffentlich zugänglich. Dieser Endpunkt verarbeitet browserbasierte föderierte Authentifizierung und kann für Phishing-Angriffe und Session-Fixation über manipulierte wauth/wctx-Parameter eingesetzt werden.

### Behebung

- Die `wreply`- und `wctx`-Parameter gegen eine registrierte Allowlist validieren.
- Auf ungewöhnliche Federation-Partner-Referenzen in wauth-Parametern überwachen.

---

## vendor-pingfederate-admin | PingFederate-Admin-Konsole Zugänglich | CRITICAL

Die PingFederate-administrative Konsole ist öffentlich zugänglich. Diese Oberfläche steuert alle Federation-Konfigurationen, Partner-Verbindungen, OAuth-Clients und Authentifizierungsrichtlinien. Öffentliche Exposition erzeugt ein erhebliches Risiko für nicht autorisierte Konfigurationsänderungen.

### Behebung

- Admin-Konsolen-Zugriff ausschließlich auf interne Management-Netzwerke einschränken.
- Admin-Oberfläche hinter VPN mit MFA-Anforderung platzieren.

---

## vendor-authentik-user-api | Authentik-Users-API Zugänglich | HIGH

Die Authentik-Users-API ist zugänglich. Falls nicht authentifizierter Zugriff erlaubt ist, ermöglicht dies vollständige Benutzer-Enumeration und potenziell Kontomanipulation, Gruppenmitgliedschaftsänderungen und Berechtigungs-Eskalation.

### Behebung

- Authentik-API erfordert eine gültige Sitzung oder ein API-Token. Verifizieren, dass kein anonymer Zugriff erlaubt ist.
- API-Zugriff auf autorisierte Dienst-Accounts beschränken.

---

## vendor-azure-legacy-auth | Azure-AD Legacy-Authentifizierungsendpunkt Zugänglich | HIGH

Der Azure-AD-Legacy-Authentifizierungsendpunkt (`/common/oauth2/token`) ist zugänglich. Dieser Endpunkt akzeptiert Benutzernamen/Passwort-Credentials direkt (ROPC-Flow) und ist ein primäres Ziel für Credential-Stuffing gegen Microsoft-365-Umgebungen, da er MFA und Conditional Access umgeht.

### Behebung

- Legacy-Authentifizierung in Entra-ID-Conditional-Access blockieren: Richtlinie erstellen, die alle Legacy-Auth-Client-Apps blockiert.
- Anmeldeprotokolle auf Legacy-Authentifizierungsversuche überwachen.
- Alle Anwendungen auf moderne Authentifizierungsprotokolle migrieren.
