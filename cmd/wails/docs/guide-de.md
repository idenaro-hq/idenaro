# Idenaro - Benutzerhandbuch

Idenaro ist ein IAM-Fehlkonfigurationsscanner. Er analysiert Identity- und Access-Management-Endpunkte und identifiziert Sicherheitsschwachstellen - ohne Zugangsdaten zu benötigen oder Zielsysteme zu verändern. Alle Prüfungen sind rein lesend: Es werden keine Authentifizierungsversuche unternommen und keine Daten geschrieben.

## Einen Scan durchführen

### Ziele hinzufügen

Geben Sie einen oder mehrere Hostnamen in das Feld **Ziele** ein. Bestätigen Sie jeden Eintrag mit **Enter** oder **Leertaste**. Unterstützte Formate:

- `auth.beispiel.de`
- `auth.beispiel.de:8443`
- `https://auth.beispiel.de`

Ein Ziel lässt sich durch Klicken auf das entsprechende Chip-Element im Eingabefeld entfernen.

### Schnellvorlagen

Vorlagen aktivieren eine vordefinierte Modulauswahl für gängige Szenarien:

- **Full scan** - Alle Module. Umfassendste Prüfung, dauert am längsten.
- **OIDC / OAuth2** - Discovery-Dokument, Flows, Redirect-URIs, Token-Algorithmen.
- **Headers & Cookies** - HTTP-Sicherheitsheader, CSP und Cookie-Attribute.
- **NIS2 Compliance** - Module, die den Anforderungen aus NIS2 Art. 21 zugeordnet sind.
- **Quick check** - Schnellster Scan mit den wichtigsten Prüfungen.

### Modulauswahl

Einzelne Module können ein- und ausgeschaltet werden. Mit **Alle auswählen** / **Alle abwählen** lassen sich alle Module gleichzeitig steuern. Der Scan führt nur die aktivierten Module aus.

### Optionen

- **TLS-Verifizierung überspringen** - Zertifikatsprüfung deaktivieren. Für interne Ziele mit selbstsignierten Zertifikaten.
- **Zeitlimit** - HTTP-Anfrage-Timeout pro Modul (10-120 Sekunden). Bei langsamen oder weit entfernten Zielen erhöhen.

### Scan starten und abbrechen

Klicken Sie auf **Scan starten**. Ein Fortschrittsbalken zeigt die abgeschlossenen Modulprüfungen an. Mit **Abbrechen** kann ein laufender Scan unterbrochen werden.

---

## Ergebnisse verstehen

### Risiko-Score

Der Risiko-Score (0-100) fasst gewichtete Befunde aller Schweregrade zusammen:

- **0-24 - Sicher**: wenige oder keine nennenswerten Befunde
- **25-49 - Moderat**: Probleme vorhanden, HIGH-Befunde innerhalb von 30 Tagen beheben
- **50-74 - Gefährdet**: erhebliche Lücken, CRITICAL- und HIGH-Befunde umgehend adressieren
- **75-100 - Kritisch**: sofortige Behebung erforderlich

### Schweregrade

- **CRITICAL** - Ohne Authentifizierung oder mit minimalem Aufwand ausnutzbar. Sofort beheben.
- **HIGH** - Erhebliches Risiko, mit moderatem Aufwand wahrscheinlich ausnutzbar.
- **MEDIUM** - Unter bestimmten Bedingungen oder in Kombination mit anderen Schwachstellen ausnutzbar.
- **LOW** - Schwachstellen in der Tiefenverteidigung, die im Rahmen geplanter Wartung behoben werden sollten.
- **INFO** - Informative Beobachtungen ohne direkten Angriffsvektor.
- **CHAIN** - Kombiniertes Risiko: Zwei oder mehr gleichzeitig auftretende Schwachstellen bilden einen Angriffspfad.

### Befunde filtern

Verwenden Sie die Schweregrad-Filterschaltflächen, um sich auf einen bestimmten Risikobereich zu konzentrieren. Das Suchfeld durchsucht Titel, Beschreibung, Modulname und NIS2-Artikelreferenzen.

### Kontextbezogene Hilfe

Klicken Sie auf die **?**-Schaltfläche eines Befundkartens, um die vollständige Dokumentationsseite mit technischem Hintergrund, Behebungsschritten und NIS2-Zuordnung zu öffnen.

---

## Ergebnisse exportieren

- **HTML** - Formatierter Bericht für Stakeholder und Prüfer.
- **JSON** - Maschinenlesbarer Export für SIEM-Integration, Ticket-Systeme oder eigene Werkzeuge.

Beide Exporte führen den Scan gegen den ausgewählten Host und die ausgewählten Module erneut aus, bevor die Ausgabe erzeugt wird.

---

## NIS2-Compliance-Leitfaden

Der **NIS2-Leitfaden** ordnet Befunde den Pflichten aus Art. 21 der NIS2-Richtlinie zu. Jede Artikelseite listet die relevanten Tags auf und erläutert, welche Arten von Befunden abgedeckt sind. Nutzen Sie diese Ansicht zur Vorbereitung von Nachweisen für Compliance-Bewertungen oder zur Priorisierung von Behebungsmaßnahmen nach regulatorischen Fristen.

---

## Befund-Referenz

Die **Befund-Referenz** dokumentiert jeden Prüfschritt des Scanners, gegliedert nach Modulen. Jede Modulseite beschreibt, was das Modul tut und welche Prüfungen es durchführt. Einzelne Befundseiten enthalten:

- **Technischer Hintergrund**: Warum der Befund relevant ist und was ein Angreifer damit tun könnte
- **Behebung**: Konkrete Konfigurationsschritte zur Beseitigung des Problems
- **NIS2-Zuordnung**: Welchem Art.-21-Gebot der Befund entspricht (sofern zutreffend)

Die Befund-Referenz ist über die Seitenleiste erreichbar. Ein Klick auf **?** bei einem Befund in der Ergebnisansicht öffnet direkt die Dokumentationsseite dieses Befunds.
