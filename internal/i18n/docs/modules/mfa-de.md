## mfa-overview | MFA | 

Das MFA-Modul analysiert Authentifizierungsseiten und -flows auf Multi-Faktor-Authentifizierungs-Abdeckung. Es prüft sichtbare UI-Elemente, JavaScript und Endpunkt-Antworten auf MFA-Indikatoren, schwache Methoden, Umgehungsmöglichkeiten und exponierte Enrollment-Oberflächen.

### Durchgeführte Prüfungen

- Vorhandensein von MFA-Indikatoren auf Login- und Challenge-Seiten
- Erkennung schwacher MFA-Methoden: SMS-OTP, E-Mail-OTP
- MFA-Umgehungsmuster in der Seitenstruktur oder Antwortflows
- Auf Login- oder Einstellungsseiten exponierte MFA-Deaktivierungsoption
- Sichtbarkeit von Backup- und Recovery-Codes während des Logins
- Unauthentifizierter Zugriff auf MFA-Bypass-Endpunkte
- OTP-Einreichungs-Rate-Limiting
- Zugriff auf MFA-Enrollment-Endpunkt ohne vorherige Authentifizierung

---

## mfa-missing | Keine MFA-Indikatoren Erkannt | MEDIUM

Durch Analyse der Login-Seite wurden keine Hinweise auf Multi-Faktor-Authentifizierung gefunden. NIS2 Art. 21(2)(i) verlangt MFA für den Zugriff auf kritische Systeme. Dies ist eine heuristische Prüfung - manuelle Bestätigung wird empfohlen.

### Behebung

- MFA für alle Benutzerkonten auf IdP-Ebene aktivieren, nicht nur für Administrator-Konten.
- MFA im IdP erzwingen, damit sie nicht pro Anwendung umgangen werden kann.
- WebAuthn/FIDO2 gegenüber TOTP, Push-MFA und SMS-OTP bevorzugen.

---

## mfa-weak | Schwache MFA-Methode Erkannt (SMS/E-Mail OTP) | MEDIUM

SMS-OTP ist anfällig für SIM-Swapping, Nummernportierung und SS7-Netzwerkangriffe. E-Mail-OTP ist anfällig für E-Mail-Konto-Kompromittierung. Beide sind erheblich schwächer als TOTP oder WebAuthn und sollten nicht als primärer zweiter Faktor für privilegierte Konten verwendet werden.

### Behebung

- TOTP-Authenticator-Apps als Standard-Zweifaktor anbieten.
- WebAuthn/FIDO2-Sicherheitsschlüssel für Administratoren und privilegierte Benutzer einsetzen.
- SMS/E-Mail nur als Fallback mit angemessenen Risikokontrollen verwenden.

---

## mfa-bypass-pattern | MFA-Umgehungsmuster Erkannt | MEDIUM

Die Login-Seite enthält Muster, die darauf hinweisen, dass MFA umgangen oder unterdrückt werden kann - „Dieses Gerät merken", „30 Tage überspringen", „Nicht mehr fragen" oder ähnliche Optionen. Diese erzeugen persistente MFA-Ausnahmen, die das Angriffsfenster nach Gerätediebstahl oder Session-Hijacking verlängern.

### Behebung

- Remember-Device-Optionen für administrativen und privilegierten Zugriff deaktivieren.
- Falls aus UX-Gründen erforderlich: Vertrauensdauer auf maximal 8 Stunden begrenzen.
- Geräte-Vertrauen an Gerätezertifikate binden, nicht an Browser-Cookies.

---

## mfa-disable-option | MFA-Deaktivierungsoption Auf Login-Seite Vorhanden | HIGH

Die Login-Seite enthält eine Option zum Deaktivieren von MFA. Ein Angreifer mit Zugriff auf das Konto (via Phishing oder Credential Stuffing) kann MFA deaktivieren, bevor der legitime Benutzer es bemerkt, und damit den zweiten Faktor dauerhaft entfernen.

### Behebung

- Stufenweise Re-Authentifizierung erfordern, bevor MFA deaktiviert werden kann.
- Benachrichtigungen an die registrierte E-Mail des Benutzers senden, wenn MFA deaktiviert wird.
- Eine obligatorische Wartezeit und einen Bestätigungslink für die MFA-Entfernung implementieren.

---

## mfa-backup-codes | Backup/Recovery-Codes Im Login-Flow Exponiert | LOW

Die Login-Seite exponiert Backup- oder Recovery-Code-Optionen prominent. Backup-Codes sind statische, langlebige Credentials, die MFA vollständig umgehen. Ihre Prominenz im Login-Flow erhöht das Bewusstsein für Angreifer.

### Behebung

- Backup-Code-Optionen hinter einen zusätzlichen Schritt verlegen, nicht auf der primären Login-Seite.
- Backup-Codes auf einmalige Verwendung beschränken und nur auf Anfrage generieren.
- Backup-Code-Verwendung protokollieren und Alarme auslösen.

---

## mfa-bypass-endpoint | MFA-Bypass-Endpunkt Zugänglich | HIGH

Ein Endpunkt im Zusammenhang mit MFA-Bypass, -Überspringen oder -Deaktivieren hat mit HTTP 200 geantwortet. Dies erfordert sofortige Untersuchung - MFA darf nicht über URL-Parameter oder undokumentierte Endpunkte umgangen werden können.

### Behebung

- Den Endpunkt entfernen oder deaktivieren, falls er nicht beabsichtigt ist.
- Admin-Authentifizierung und Step-up-MFA für jeden legitimen MFA-Management-Endpunkt erfordern.
- Zugriffsprotokolle auf unautorisierte Versuche prüfen.

---

## mfa-otp-no-ratelimit | OTP Rate-Limiting Fehlt | MEDIUM

Kein Rate-Limiting oder Lockout wurde am OTP-Verifikationsendpunkt erkannt. Ohne Rate-Limiting kann ein Angreifer 6-stellige TOTP-Codes (1.000.000 Möglichkeiten) oder SMS-OTPs innerhalb des Gültigkeitsfensters brute-forcen.

### Behebung

- Lockout nach 5 fehlgeschlagenen OTP-Versuchen implementieren.
- Exponentielles Backoff zwischen Versuchen hinzufügen.
- Bei wiederholten OTP-Fehlern von derselben IP oder demselben Konto warnen.

---

## mfa-enrollment-open | MFA-Enrollment-Endpunkt Ohne Authentifizierung Zugänglich | MEDIUM

Ein MFA-Enrollment-Endpunkt ist ohne vorherige Authentifizierung zugänglich. Ein Angreifer, der zuerst auf diesen Endpunkt zugreift, kann sein eigenes MFA-Gerät für ein Zielkonto registrieren und so den legitimen Benutzer aussperren.

### Behebung

- Authentifizierung vor der MFA-Enrollment-Genehmigung erfordern.
- Bestätigung an den registrierten Kontakt des Benutzers senden, wenn MFA eingeschrieben wird.
- Admin-Genehmigung für MFA-Enrollment bei privilegierten Konten implementieren.
