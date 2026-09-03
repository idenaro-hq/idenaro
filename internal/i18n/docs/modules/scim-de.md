## scim-overview | SCIM | 

Das SCIM-Modul testet System-for-Cross-domain-Identity-Management-Endpunkte auf nicht authentifizierten Zugriff. SCIM wird von Enterprise-Verzeichnissen und IdPs zur Bereitstellung, Aktualisierung und Deprovisionierung von Benutzerkonten und Gruppenmitgliedschaften verwendet. Unauthentifizierter Zugriff ermöglicht vollständige Benutzerverzeichnis-Enumeration und potenziell Benutzererstellung oder Kontoübernahme.

### Durchgeführte Prüfungen

- Zugriff auf `/scim/v2/Users` und `/scim/v2/Groups` ohne Authentifizierung
- Exposition des SCIM-`ServiceProviderConfig`-Endpunkts, der Fähigkeitsdetails enthüllt

---

## scim-exposed | SCIM-Endpunkt Ohne Authentifizierung Zugänglich | CRITICAL

Ein SCIM-Bereitstellungsendpunkt ist öffentlich ohne Authentifizierung zugänglich. SCIM bietet vollständigen CRUD-Zugriff auf Benutzer- und Gruppenidentitäten. Unauthentifizierter Zugriff ermöglicht Massen-Benutzer-Enumeration, Kontoanlegung, Gruppenmanipulation und Privileg-Eskalation.

### Behebung

- Bearer-Token-Authentifizierung auf allen SCIM-Endpunkten erfordern.
- SCIM-Zugriff auf den IP-Bereich des Bereitstellungssystems einschränken.
- SCIM-Bearer-Tokens nach einem regulären Zeitplan rotieren (90 Tage oder weniger).
- Audit-Logging für alle SCIM-Operationen aktivieren.

---

## scim-config-exposed | SCIM ServiceProviderConfig Zugänglich | MEDIUM

Der SCIM-ServiceProviderConfig-Endpunkt enthüllt die SCIM-Implementierungsdetails, unterstützte Features und Authentifizierungsschemen. Obwohl weniger sensitiv als Benutzerdaten, erleichtert er die Aufklärung des Identity-Bereitstellungssystems.

### Behebung

- Authentifizierung für alle SCIM-Endpunkte einschließlich Konfigurations- und Schema-Endpunkten erfordern.
