## saml-overview | SAML | 

Das SAML-Modul prüft SAML-Identity-Provider- und Service-Provider-Konfigurationen durch Abrufen und Analysieren öffentlich zugänglicher Metadaten-Dokumente. Es analysiert Signaturanforderungen, Zertifikatszustand, Binding-Auswahl und Single-Logout-Konfiguration ohne Zugangsdaten.

### Durchgeführte Prüfungen

- Zugänglichkeit und Struktur des Metadaten-Dokuments
- Anforderung signierter AuthnRequests beim IdP
- HTTPS-Durchsetzung für SSO- und ACS-Endpunkte
- Verwendete Binding-Typen: HTTP-Redirect, SOAP, Artifact
- SP-Signatur- und Verschlüsselungsschlüssel-Konfiguration
- Zertifikatsablauf, kurze Gültigkeit und Wiederverwendung zwischen Signierung und Verschlüsselung
- Vorhandensein des Single-Logout-Endpunkts (SLO)

---

## saml-metadata | SAML-Metadaten Öffentlich Zugänglich | INFO

SAML-Metadaten sind ohne Authentifizierung zugänglich. Dies ist für föderiertes SSO erwartet, legt aber IdP- und SP-Konfiguration, Endpunkt-URLs und Signierzertifikate offen. Überprüfen, ob die offengelegten Informationen beabsichtigt sind und alle Zertifikate aktuell sind.

### Was zu prüfen ist

- Bestätigen, dass Zertifikate nicht abgelaufen sind oder bald ablaufen.
- Überprüfen, dass alle Endpunkt-URLs HTTPS verwenden.
- Sicherstellen, dass keine sensiblen internen Hostnamen in den Metadaten erscheinen.

---

## saml-unsigned-authn | SAML IdP Erfordert Keine Signierten AuthnRequests | MEDIUM

`WantAuthnRequestsSigned=false` bedeutet, der IdP akzeptiert nicht signierte Authentifizierungsanfragen. Angreifer können Authentifizierungsanfragen fälschen, NameID-Formate manipulieren, unerwünschte Attribute anfordern oder ForceAuthn missbrauchen, um bestehende Sitzungen zu umgehen.

### Behebung

- `WantAuthnRequestsSigned="true"` in der IdP-Konfiguration setzen.
- Sicherstellen, dass alle SPs ihre AuthnRequests signieren und der IdP Signaturen validiert.

---

## saml-sso-http | SAML SSO-Endpunkt Verwendet Kein HTTPS | HIGH

Der SingleSignOnService-Endpunkt verwendet HTTP. Über HTTP übertragene SAML-Assertions sind für Netzwerkbeobachter sichtbar und können von Angreifern im selben Netzwerk abgefangen und wiedergespielt werden.

### Behebung

- Alle SAML-Endpunkte ausschließlich auf HTTPS konfigurieren.
- HTTP-Anfragen mit einer permanenten 301-Weiterleitung auf HTTPS umleiten.

---

## saml-redirect-binding | SAML HTTP-Redirect-Binding Im Einsatz | LOW

Das HTTP-Redirect-Binding überträgt SAML-Nachrichten als URL-Query-Parameter. Dies begrenzt die Nachrichtengröße und setzt kodierte Assertions Server-Protokollen und Browser-Verläufen aus. Das HTTP-POST-Binding wird für Antworten bevorzugt.

### Behebung

- HTTP-POST-Binding für SingleSignOnService-Antworten verwenden.
- HTTP-Redirect ist für AuthnRequests vom SP akzeptabel, aber nicht für IdP-Antworten mit Assertions.

---

## saml-soap-binding | SAML SOAP-Binding Exponiert | LOW

Das SOAP-Binding ist in den SAML-Metadaten aufgeführt. SOAP-Bindings sind in modernen Deployments ungewöhnlich, erweitern die Angriffsfläche und deuten oft auf Legacy-Konfiguration hin. Falsch konfigurierte SOAP-Endpunkte können für SSRF missbraucht werden.

### Behebung

- SOAP-Binding entfernen, sofern nicht ausdrücklich durch einen Federation-Partner erforderlich.
- SOAP-Endpunkt auf Authentifizierungsanforderungen und Zugriffskontrollen prüfen.

---

## saml-artifact-binding | SAML Artifact-Binding Exponiert | LOW

Das Artifact-Binding erfordert, dass der SP Artifacts über eine Back-Channel-Anfrage an den ArtifactResolutionService des IdP auflöst. Falsch konfigurierte Artifact-Resolution-Endpunkte können für SSRF missbraucht werden, und das Binding fügt Komplexität hinzu, die selten gerechtfertigt ist.

### Behebung

- Artifact-Binding entfernen, sofern nicht ausdrücklich erforderlich.
- Falls verwendet, sicherstellen, dass der ArtifactResolutionService gegenseitiges TLS oder Client-Authentifizierung erfordert.

---

## saml-sp-unsigned-assertions | SAML SP Erfordert Keine Signierten Assertions | HIGH

`WantAssertionsSigned=false` bedeutet, der SP akzeptiert SAML-Assertions ohne Signaturverifizierung. Ein Angreifer, der eine Assertion abfangen oder injizieren kann, kann sich ohne gültige IdP-Signatur als beliebiger Benutzer authentifizieren.

### Behebung

- `WantAssertionsSigned="true"` in den SP-Metadaten setzen.
- Den IdP konfigurieren, Assertions für diesen SP immer zu signieren.
- Verifizieren, dass Signierung sowohl auf Assertion- als auch auf Response-Ebene erzwungen wird.

---

## saml-sp-unsigned-authn | SAML SP Signiert AuthnRequests Nicht | MEDIUM

Der SP signiert ausgehende Authentifizierungsanfragen nicht (`AuthnRequestsSigned=false`). Nicht signierte Anfragen ermöglichen Man-in-the-Middle-Manipulation von NameID-Format, ForceAuthn-Flags und angeforderten Attributmengen.

### Behebung

- Request-Signierung am SP aktivieren und `AuthnRequestsSigned="true"` setzen.
- Den IdP konfigurieren, Request-Signaturen von diesem SP zu validieren.

---

## saml-no-encryption-key | SAML SP Hat Keinen Verschlüsselungsschlüssel | MEDIUM

Die SP-Metadaten enthalten keinen Verschlüsselungsschlüssel-Deskriptor. Der IdP kann Assertions nicht verschlüsseln, d. h. Benutzeridentitätsattribute und Rollenansprüche werden im Klartext übertragen. Wird TLS degradiert oder ein Intermediär kompromittiert, werden Attribute exponiert.

### Behebung

- Einen Verschlüsselungsschlüssel-Deskriptor zu den SP-Metadaten hinzufügen.
- Den IdP konfigurieren, Assertions mit dem öffentlichen Schlüssel des SP zu verschlüsseln.
- Separate Schlüsselpaare für Signierung und Verschlüsselung verwenden.

---

## saml-acs-http | SAML ACS-Endpunkt Verwendet Kein HTTPS | HIGH

Der AssertionConsumerService-Endpunkt verwendet HTTP. An diesen Endpunkt gesendete SAML-Assertions werden im Klartext übertragen, was Benutzeridentitätsattribute, Sitzungstoken und Rollenansprüche für Netzwerkbeobachter exponiert.

### Behebung

- ACS-Endpunkt ausschließlich über HTTPS bereitstellen.
- SP-Metadaten aktualisieren, um die HTTPS-ACS-URL zu reflektieren.
- HTTP-ACS-Anfragen auf HTTPS weiterleiten.

---

## saml-cert-expired | SAML-Signierzertifikat Abgelaufen | HIGH

Das SAML-Signierzertifikat in den Metadaten ist abgelaufen. Dies führt bei IdPs, die die Zertifikatsgültigkeit erzwingen, zum vollständigen Ausfall der Federation. Einige permissive Implementierungen können auf das Akzeptieren nicht signierter Assertions zurückfallen und so eine Sicherheitslücke erzeugen.

### Behebung

- Sofort ein neues Zertifikat generieren.
- Rolling-Rotation verwenden: neues Zertifikat in den Metadaten veröffentlichen, bevor es für die Signierung aktiviert wird.
- Alle SP-Metadaten und Federation-Partner-Konfigurationen aktualisieren.
- Innerhalb des geplanten Wartungsfensters rotieren, um Ausfallzeiten zu minimieren.

---

## saml-cert-expiring | SAML-Signierzertifikat Läuft Bald Ab | MEDIUM

Das SAML-Signierzertifikat läuft innerhalb von 30 Tagen ab. Unterlässt man die Rotation vor Ablauf, kommt es zu Authentifizierungsausfällen bei allen föderativen Diensten, die von diesem Zertifikat abhängen.

### Behebung

- Sofort mit der Zertifikatsrotation beginnen - vollständigen Rollout einschließlich Partner-Metadaten-Updates einplanen.
- Automatisiertes Zertifikats-Ablauf-Monitoring bei 60, 30 und 7 Tagen implementieren.

---

## saml-cert-long-lived | SAML-Zertifikat Hat Sehr Lange Gültigkeit | LOW

Das SAML-Signierzertifikat besitzt eine Gültigkeitsdauer von mehr als 3 Jahren. Langlebige Zertifikate verlängern das Auswirkungsfenster bei Kompromittierung des privaten Schlüssels - der Schlüssel bleibt für die gesamte Gültigkeitsdauer zum Signieren von Tokens verwendbar.

### Behebung

- Neue Zertifikate mit einer maximalen Gültigkeitsdauer von 2 Jahren ausstellen.
- Automatisierte Rotation auf geplanter Basis implementieren (jährlich empfohlen).

---

## saml-same-cert | SAML Gleiches Zertifikat Für Signierung Und Verschlüsselung | LOW

Die Signier- und Verschlüsselungsschlüssel-Deskriptoren referenzieren dasselbe Zertifikat. Best Practice erfordert separate Schlüssel: Die Kompromittierung des Signierschlüssels gefährdet auch die Assertions-Vertraulichkeit, und die Kompromittierung des Verschlüsselungsschlüssels könnte für Fälschungen genutzt werden.

### Behebung

- Separate Schlüsselpaare für Signierung und Verschlüsselung generieren.
- IdP-Konfiguration und SP-Metadaten aktualisieren, um die getrennten Schlüssel zu verwenden.

---

## saml-no-slo | SAML Single Logout Nicht Konfiguriert | MEDIUM

Kein Single-Logout-Dienst (SLO) ist in den IdP-Metadaten konfiguriert. Ohne SLO beendet das Abmelden beim IdP keine Sitzungen bei verbundenen Service Providern, sodass Benutzer bei SPs authentifiziert bleiben, selbst wenn sie glauben, sich abgemeldet zu haben.

### Behebung

- Einen SLO-Endpunkt in den IdP-Metadaten konfigurieren.
- Sicherstellen, dass alle SPs SLO-Handling implementieren und auf Logout-Anfragen reagieren.
- Den vollständigen Logout-Flow über alle registrierten SPs testen.

---

## saml-idp-signing-ok | SAML IdP erfordert signierte AuthnRequests | INFO

`WantAuthnRequestsSigned=true` ist gesetzt - der IdP validiert, dass alle eingehenden Authentifizierungsanfragen eine gültige SP-Signatur tragen. Dies verhindert Anfragen-Fälschung und blockiert IdP-initiierte SSO-Angriffe, bei denen unsignierte Anfragen NameID-Formate oder ForceAuthn-Flags manipulieren könnten.

### Behebung

- Kein Handlungsbedarf.

---

## saml-sp-signing-ok | SAML SP erzwingt Assertion-Signierung, Request-Signierung und Verschlüsselung | INFO

Die SP-Metadaten erfordern signierte Assertions (`WantAssertionsSigned=true`), signieren ausgehende AuthnRequests (`AuthnRequestsSigned=true`) und veröffentlichen einen Verschlüsselungsschlüssel-Deskriptor. Assertions sind gegen Fälschung und Abhören geschützt.

### Behebung

- Kein Handlungsbedarf.

---

## saml-bindings-ok | SAML SSO-Endpunkte verwenden sichere Bindings und HTTPS | INFO

Alle SingleSignOnService-Endpunkte verwenden HTTPS, und keine unsicheren Bindings (SOAP, Artifact) wurden gefunden. Das HTTP-Redirect-Binding ist nicht vorhanden oder wird nur für Anfragen verwendet, nicht für Antworten mit Assertions.

### Behebung

- Kein Handlungsbedarf.
