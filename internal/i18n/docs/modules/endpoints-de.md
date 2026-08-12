## endpoints-overview | Endpunkte | 

Das Endpunkte-Modul prüft auf sensitive administrative, diagnostische und Infrastruktur-Endpunkte, die ohne Authentifizierung auf dem Zielhost erreichbar sind. Die Exposition dieser Endpunkte bietet typischerweise direkte Ausnutzungspfade für Privileg-Eskalation, Datenextraktion oder Remote-Code-Execution.

### Durchgeführte Prüfungen

- Admin-Panel-Pfade (`/admin`, `/administrator`, `/wp-admin` etc.)
- Spring-Boot-Actuator-Endpunkte: `env`, `heapdump`, `mappings`, `beans`
- Environment-Dateien: `.env`, `.env.production`, `.env.local`
- Debug- und Diagnose-Endpunkte
- ADFS-WS-Trust-Endpunkt (`/adfs/services/trust`)
- Exchange Web Services (EWS): `/ews/exchange.asmx`
- Kubernetes-API-Server-Zugänglichkeit
- HashiCorp-Vault-HTTP-API
- GraphQL-Introspection-Query aktiviert

---

## endpoints-admin | Admin-Panel Öffentlich Zugänglich | HIGH

Eine administrative Oberfläche ist aus dem öffentlichen Internet zugänglich. Admin-Panels sind bevorzugte Ziele für Credential-Stuffing, Brute-Force-Angriffe und Ausnutzung bekannter IdP-Schwachstellen. Ein einziges kompromittiertes Admin-Konto gewährt vollständige Systemkontrolle.

### Behebung

- Admin-Oberflächen auf interne Netzwerke oder ausschließlichen VPN-Zugriff am Netzwerkperimeter beschränken.
- Keycloak: `--hostname-admin` verwenden, um die Admin-Konsole auf einem separaten internen Hostnamen bereitzustellen.
- MFA für alle administrativen Authentifizierungen erfordern.

---

## endpoints-actuator-env | Spring-Boot-Umgebungsvariablen Exponiert | CRITICAL

Der Spring-Boot-Actuator-Endpunkt `/actuator/env` ist öffentlich zugänglich. Dieser Endpunkt legt alle Umgebungsvariablen offen, einschließlich Datenbankpasswörter, API-Schlüssel, OAuth-Geheimnisse und alle anderen als Umgebungsvariablen konfigurierten Secrets.

### Behebung

- `/actuator/env` sofort deaktivieren oder einschränken.
- Alle möglicherweise exponierten Secrets rotieren.
- Management-Server an einen internen Port binden: `management.server.address=127.0.0.1`

---

## endpoints-dotenv | Environment-Datei (.env) Exponiert | CRITICAL

Die `/.env`-Datei ist öffentlich zugänglich. Diese Datei enthält typischerweise Datenbank-Credentials, API-Schlüssel, OAuth-Client-Geheimnisse, Verschlüsselungsschlüssel und andere sensible Konfigurationen. Alle Secrets in dieser Datei müssen als kompromittiert betrachtet werden.

### Behebung

- Die .env-Datei sofort aus dem Web-Root entfernen.
- Alle in der Datei enthaltenen Secrets rotieren.
- Webserver so konfigurieren, dass der Zugriff auf Dotfiles verweigert wird.
- Secrets in einem Secrets-Manager (Vault, AWS Secrets Manager) statt in Dateien speichern.

---

## endpoints-debug | Debug-Endpunkt Exponiert | HIGH

Ein Debug-Endpunkt (/debug, /debug/vars, /actuator) ist öffentlich zugänglich. Debug-Endpunkte legen Laufzeit-Konfiguration, Speicherzustand, Goroutine-Stacks, Umgebungsvariablen und interne Topologie offen - all das erleichtert gezielte Angriffe.

### Behebung

- Alle Debug-Endpunkte aus Produktions-Deployments entfernen.
- Falls Monitoring erforderlich, an interne Schnittstelle binden und nach IP einschränken.
- Authentifizierung für alle Monitoring- und Metrik-Endpunkte erfordern.

---

## endpoints-adfs-wstrust | ADFS WS-Trust-Endpunkt Exponiert | CRITICAL

Der ADFS-WS-Trust-`usernamemixed`-Endpunkt akzeptiert Klartext-Benutzernamen und -Passwörter. Dieser Endpunkt umgeht vollständig MFA und Conditional-Access-Richtlinien und ist das primäre Ziel für Password-Spray-Angriffe gegen Microsoft-Umgebungen.

### Behebung

- Diesen Endpunkt am Perimeter blockieren, wenn er nicht für Legacy-Clients benötigt wird.
- Entra-ID-Smart-Lockout und Anmelderisiko-Richtlinien aktivieren.
- Legacy-Clients auf moderne Authentifizierungsprotokolle migrieren.

---

## endpoints-ews | Exchange Web Services (EWS) Exponiert | CRITICAL

Der Exchange-Web-Services-Endpunkt unterstützt Basic-Authentifizierung und ist ein primäres Ziel für Credential-Stuffing- und Password-Spray-Angriffe. In den meisten Konfigurationen umgeht er MFA und ist für einen Großteil der Office-365-Konto-Kompromittierungen verantwortlich.

### Behebung

- Basic-Authentifizierung auf EWS deaktivieren.
- Legacy-Authentifizierung in Entra-ID-Conditional-Access blockieren.
- EWS-Clients auf die Microsoft-Graph-API migrieren.

---

## endpoints-k8s | Kubernetes-API Zugänglich | CRITICAL

Der Kubernetes-API-Server ist öffentlich zugänglich. Eine nicht authentifizierte oder schwach authentifizierte Kubernetes-API bietet Zugriff auf Secrets (einschließlich OAuth-Tokens und Zertifikate), ermöglicht Workload-Manipulation und kann zu vollständiger Cluster-Übernahme führen.

### Behebung

- Kubernetes-API-Zugriff ausschließlich auf interne Netzwerke einschränken.
- Anonyme Authentifizierung deaktivieren: `--anonymous-auth=false`
- RBAC und Audit-Logging aktivieren.
- Netzwerkrichtlinien verwenden, um API-Server-Zugriff auf autorisierte Nodes zu beschränken.

---

## endpoints-vault | HashiCorp-Vault-API Zugänglich | HIGH

Die HashiCorp-Vault-API ist öffentlich zugänglich. Vault speichert die sensibelsten Credentials in der Umgebung. Auch wenn Authentifizierung erforderlich ist, erzeugt öffentliche Exposition unnötige Angriffsfläche gegen das Secret-Management-System.

### Behebung

- Vault-API-Zugriff auf interne Netzwerke oder VPN einschränken.
- Vault-Audit-Logging aktivieren.
- Netzwerkseitige Zugangskontrolle als Defense-in-Depth-Maßnahme verwenden.

---

## endpoints-graphql-introspection | GraphQL-Introspection Aktiviert | MEDIUM

GraphQL-Introspection ist in der Produktion aktiviert. Introspection ermöglicht jedem Client die vollständige API-Schema-Enumeration einschließlich aller Types, Queries, Mutations und Argumente. Auf Identity-APIs enthüllt dies alle administrativen, Benutzerverwaltungs- und Auth-Routen.

### Behebung

- Introspection in der Produktion deaktivieren: die meisten GraphQL-Bibliotheken unterstützen eine Option `introspection: false`.
- Falls Introspection für die Entwicklung benötigt wird, auf authentifizierte Admin-Benutzer beschränken.
