Verkettete Befunde repräsentieren ein kombiniertes Risiko, das gleichzeitig mehrere Anforderungen des Artikel 21(2) überspannt. Wenn zwei oder mehr verwandte Fehlkonfigurationen gemeinsam erkannt werden, erzeugt die Kombination ein Risiko, das größer ist als die Summe seiner Teile - und wird mehreren spezifischen Artikeln zugeordnet: Lieferkettensicherheit (d), sichere Entwicklung (e) und Risikoanalyse (a).

### Warum kombinierte Risiken für NIS2 relevant sind

NIS2 Art. 21(1) verpflichtet Einrichtungen, „geeignete und verhältnismäßige technische, operative und organisatorische Maßnahmen zu treffen, um die Risiken für die Sicherheit von Netz- und Informationssystemen zu steuern". Das Wort „geeignet" impliziert, dass der Kontext eine Rolle spielt - ein einzelner fehlender Header mag akzeptabel sein, aber derselbe fehlende Header in Kombination mit einem exponierten Admin-Panel und fehlendem MFA stellt ein systemisches Versagen dar, das NIS2 explizit adressiert.

### Beispiele für Verkettungsbedingungen

- **Fehlendes MFA + exponiertes Admin-Panel:** Ein einziges kompromittiertes Passwort gewährt vollständigen administrativen Zugriff. Art. 21(2)(i) und (j) verlangen sowohl Zugangskontrolle als auch MFA - ihr kombiniertes Fehlen ist eine kritische Compliance-Lücke.
- **CORS-Fehlkonfiguration + Auth-Endpunkt:** Überschneidet gleichzeitig Art. 21(2)(e) (sichere Entwicklung) und Art. 21(2)(i) (Zugangskontrolle).
- **Impliziter Flow + schwache CSP:** Eine XSS-Schwachstelle (Art. 21(2)(e)) kombiniert mit Tokens in URL-Fragmenten (Art. 21(2)(i)) erzeugt eine Token-Diebstahl-Angriffskette.

### Behebungspriorität

Verkettete Befunde sollten als höchste Behebungspriorität behandelt werden. Alle beitragenden Befunde müssen gemeinsam als koordinierte Maßnahme adressiert werden - nicht einzeln - da das Beheben einer Komponente bei offenen anderen ein falsches Sicherheitsgefühl erzeugen kann, ohne die Angriffsfläche tatsächlich wesentlich zu reduzieren.
