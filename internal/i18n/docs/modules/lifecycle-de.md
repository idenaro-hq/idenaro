## lifecycle-overview | Konto-Lebenszyklus | 

Das Konto-Lebenszyklus-Modul prüft Benutzerkontoverwaltungs-Endpunkte auf nicht authentifizierten Zugriff. Diese Endpunkte steuern Benutzererstellung, Privileg-Zuweisung und Sitzungsverwaltung - Exposition kann zu Kontoübernahme, unautorisierter Registrierung oder Privileg-Eskalation ohne jegliche Zugangsdaten führen.

### Durchgeführte Prüfungen

- Imitierungsendpunkt ohne Authentifizierung zugänglich
- Offener Benutzer-Selbstregistrierungsendpunkt
- Admin-Benutzereinladungsendpunkt zugänglich
- Kontosperrungsaufhebungsendpunkt ohne Authentifizierung zugänglich
- Passwortänderungsendpunkt ohne vorherige Authentifizierung zugänglich (informativ)

---

## lifecycle-impersonate | Imitierungsendpunkt Zugänglich | CRITICAL

Ein Admin-Imitierungsendpunkt ist öffentlich zugänglich. Imitierung erlaubt Administratoren, als andere Benutzer zu agieren. Bei Zugänglichkeit ohne starke Authentifizierung kann jeder Angreifer, der den Endpunkt erreichen kann, auf jedes Benutzerkonto im System eskalieren.

### Behebung

- Step-up-MFA-Re-Authentifizierung erfordern, bevor eine Imitierungssitzung beginnt.
- Imitierung auf namentlich genannte Super-Admin-Konten beschränken.
- Jedes Imitierungsereignis mit vollständigem Audit-Trail protokollieren und per E-Mail/SIEM alarmieren.
- Imitierungssitzungen nach 15 Minuten automatisch beenden.

---

## lifecycle-register-open | Offene Benutzerregistrierung | MEDIUM

Die Benutzerregistrierung ist ohne Einladung oder Genehmigung öffentlich zugänglich. Offene Registrierung ermöglicht Angreifern, Konten zu erstellen und auf interne APIs zuzugreifen, Features auf Schwachstellen zu testen und in einigen Konfigurationen über Self-Service-Rollenauswahl auf höhere Privilegstufen zu eskalieren.

### Behebung

- E-Mail-Domain-Verifikation oder einladungsbasierte Registrierung erfordern.
- Bestätigen, dass die Registrierung eine E-Mail-Verifizierung erfordert.
- CAPTCHA und Rate-Limiting bei der Registrierung implementieren.
- Sicherstellen, dass neue Konten während der Registrierung keine Rollen oder Berechtigungen selbst zuweisen können.

---

## lifecycle-invite | Admin-Einladungsendpunkt Zugänglich | HIGH

Ein administrativer Einladungsverwaltungsendpunkt ist zugänglich. Falls unauthentifizierter Zugriff erlaubt ist, können Angreifer Einladungen an beliebige E-Mail-Adressen senden oder eingeladene Benutzer aufzählen.

### Behebung

- Einladungsverwaltung ausschließlich auf authentifizierte Administratoren beschränken.
- Alle gesendeten Einladungen protokollieren und bei ungewöhnlichen Mengen alarmieren.

---

## lifecycle-unlock | Kontoentsperrungsendpunkt Zugänglich | MEDIUM

Ein Kontoentsperrungsendpunkt ist öffentlich zugänglich. Ohne ordnungsgemäße Kontrolle kann dies das Umgehen von Kontosperrungsrichtlinien ermöglichen - einer Sicherheitskontrolle, die Brute-Force-Angriffe verlangsamen soll.

### Behebung

- Starke Identitätsverifizierung vor der Kontoentsperrung erfordern.
- Entsperrungsbestätigung an die registrierte E-Mail des Benutzers senden.
- Alle Kontoentsperrungsvorgänge protokollieren und alarmieren.

---

## lifecycle-password-change | Passwortänderungsendpunkt Zugänglich | INFO

Ein Passwortänderungsendpunkt ist zugänglich. Verifizieren, dass das aktuelle Passwort vor der Änderung erfordert wird (verhindert CSRF-basierte Passwortänderungen) und CSRF-Tokens bei Formulareinreichungen verwendet werden.

### Was zu verifizieren ist

- Verifizierung des aktuellen Passworts vor Akzeptieren eines neuen Passworts erfordern.
- CSRF-Tokens im Passwortänderungsformular verwenden.
- MFA-Re-Authentifizierung für Passwortänderungen in Betracht ziehen.
