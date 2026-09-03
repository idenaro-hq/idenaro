## enumeration-overview | Enumeration | 

Das Enumeration-Modul testet Authentifizierungs-Flow-Endpunkte auf Antwortunterschiede, die verraten, ob ein eingegebener Benutzername oder eine E-Mail-Adresse registriert ist. User-Enumeration ermöglicht Konto-Targeting bei Credential-Stuffing-, Brute-Force- und Social-Engineering-Angriffen.

### Durchgeführte Prüfungen

- Passwort-Reset-Formular: unterschiedliche Antworttexte für gültige vs. ungültige Adressen
- Login-Fehlermeldungen: unterschiedliche Meldungen für „Benutzer nicht gefunden" vs. „falsches Passwort"
- Kontostatus-Disclosure: gesperrtes, suspendiertes oder deaktiviertes Konto im Login-Flow angezeigt
- Benutzerdaten-API-Endpunkte ohne Authentifizierung zugänglich

---

## enum-reset-wording | User-Enumeration Via Passwort-Reset-Text | MEDIUM

Die Passwort-Reset-Seite gibt unterschiedliche Meldungen für existierende und nicht existierende Konten zurück („Benutzer nicht gefunden", „E-Mail nicht gefunden", „kein Konto mit dieser E-Mail"). Angreifer können dies nutzen, um eine Liste gültiger Konten für gezielte Credential-Angriffe aufzubauen.

### Behebung

- Eine identische Antwort für alle Reset-Anfragen zurückgeben: „Wenn ein Konto mit dieser E-Mail-Adresse existiert, erhalten Sie einen Reset-Link."
- Sicherstellen, dass die Antwortzeiten konsistent sind (Constant-Time-Operationen verwenden).
- Rate-Limiting am Reset-Endpunkt implementieren.

---

## enum-login-wording | User-Enumeration Via Login-Fehlermeldung | MEDIUM

Die Login-Seite unterscheidet zwischen „Benutzer nicht gefunden" und „falsches Passwort"-Fehlern, was Angreifern ermöglicht, gültige Benutzernamen zu bestimmen, bevor passwortbasierte Angriffe durchgeführt werden.

### Behebung

- Eine generische Fehlermeldung für alle Authentifizierungsfehler zurückgeben: „Ungültige Zugangsdaten."
- In Fehlermeldungen niemals zwischen unbekanntem Benutzernamen und falschem Passwort unterscheiden.
- Sicherstellen, dass die Antwortzeiten unabhängig davon konsistent sind, ob der Benutzer existiert.

---

## enum-account-status | Kontostatus Im Login-Flow Enthüllt | MEDIUM

Der Login-Flow enthüllt spezifische Kontostände („Konto gesperrt", „Konto deaktiviert", „Konto suspendiert"). Dies bestätigt zwar die Existenz des Kontos, enthüllt aber auch sicherheitsrelevante Kontoinformationen an nicht authentifizierte Benutzer.

### Behebung

- Generische Fehlermeldungen zurückgeben, die den Kontostatus gegenüber nicht authentifizierten Benutzern nicht enthüllen.
- Kontospezifische Probleme stattdessen über die registrierte E-Mail-Adresse kommunizieren.

---

## enum-user-api | Benutzerdaten Ohne Authentifizierung Zugänglich | HIGH

Ein Benutzer-Listing- oder Such-API-Endpunkt hat JSON-Benutzerdatensätze (E-Mail, Benutzername, displayName) ohne erforderliche Authentifizierung zurückgegeben. Dies ermöglicht die Massen-Enumeration aller Benutzerkonten im System.

### Behebung

- Authentifizierung für alle Benutzerverwaltungs- und Listing-Endpunkte erfordern.
- Least-Privilege-Prinzip anwenden: normale Benutzer sollten nicht alle Konten aufzählen können.
- Paginierung und Rate-Limiting auf Benutzer-Such-Endpunkten implementieren.
