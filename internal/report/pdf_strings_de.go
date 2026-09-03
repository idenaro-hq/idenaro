package report

func deStrings() pdfStrings {
	return pdfStrings{
		HeaderTitle:     "Idenaro - NIS2-Compliance-Bewertungsbericht",
		HeaderConf:      "VERTRAULICH",
		FooterDirective: "NIS2-Richtlinie (EU) 2022/2555 | IAM-Assessment",
		FooterPage:      "Seite %d von {nb}",

		StatusNonCompliant:      "NICHT KONFORM",
		StatusRequiresAttention: "HANDLUNGSBEDARF",
		StatusLargelyCompliant:  "WEITGEHEND KONFORM",
		StatusCompliant:         "KONFORM",
		StatusNotAssessed:       "NICHT BEWERTET",

		CoverPlatform:     "IAM-Sicherheitsbewertungsplattform",
		CoverReportSub:    "Bewertungsbericht",
		CoverDirective:    "Richtlinie (EU) 2022/2555 - Artikel 21 Cybersicherheitsrisikomanagementsmaßnahmen",
		CoverMetaDate:     "Berichtsdatum:",
		CoverMetaScanner:  "Scanner:",
		CoverMetaScannerV: "IAM-Assessment durch Idenaro",
		CoverMetaType:     "Bewertungstyp:",
		CoverMetaTypeV:    "Externes Assessment - keine Zugangsdaten erforderlich",
		CoverMetaMethod:   "Methodik:",
		CoverMetaMethodV:  "Unauthentifiziertes Probing öffentlich erreichbarer Identitätsendpunkte",
		CoverMetaScope:    "Umfang:",
		CoverMetaScopeV:   "%d System(e) bewertet",
		CoverMetaClass:    "Klassifizierung:",
		CoverMetaClassV:   "VERTRAULICH - Beschränkte Weitergabe",
		CoverSystems:      "Bewertete Systeme",
		CoverConfTitle:    "VERTRAULICHKEITSHINWEIS",
		CoverConfBody: "Dieses Dokument enthält sensible Sicherheitsbewertungsergebnisse. Die Weitergabe ist auf " +
			"autorisiertes Personal mit berechtigtem Informationsbedarf beschränkt. Das Dokument darf nicht " +
			"kopiert, übermittelt oder auf Systemen gespeichert werden, die nicht für vertrauliche " +
			"Informationen zugelassen sind.",

		SecExecSummary: "Zusammenfassung",
		H2OverallRisk:  "Gesamtrisikobeurteilung",
		BodyOverallRisk: "Die folgende Tabelle fasst den Gesamtrisiko-Score je bewertetem System zusammen. " +
			"Scores reichen von 0 (keine Befunde) bis 100 (maximales Risiko in allen Kategorien). " +
			"Scores über 70 weisen auf kritisches Risiko hin, das sofortige Behebung erfordert.",
		ColSystem:          "System",
		ColRiskScore:       "Risiko-Score",
		ColCritical:        "Kritisch",
		ColHigh:            "Hoch",
		ColMedium:          "Mittel",
		H2ComplianceMatrix: "NIS2-Artikel-21-Compliance-Status",
		BodyComplianceMatrix: "Die folgende Matrix fasst den Compliance-Status für jeden bewerteten NIS2-Art.-21(2)-" +
			"Unterabsatz zusammen. Die Status werden ausschließlich aus den technischen Befunden " +
			"des Assessments abgeleitet.",
		ColArticle:   "Artikel",
		ColTitle:     "Titel",
		ColStatus:    "Status",
		ColControls:  "Kontrollen",
		ColIssues:    "Befunde",
		H2StatusDefs: "Statusdefinitionen",
		LegendRows: [5][2]string{
			{"KONFORM", "Nur informative Befunde (Kontrollen verifiziert). Keine Compliance-Lücken festgestellt."},
			{"WEITGEHEND KONFORM", "Nur Befunde mit niedrigem Schweregrad. Geringfügige Verbesserungen empfohlen."},
			{"HANDLUNGSBEDARF", "Befunde mittleren Schweregrads vorhanden. Korrekturmaßnahmen innerhalb eines definierten Zeitrahmens erforderlich."},
			{"NICHT KONFORM", "Befunde mit hohem oder kritischem Schweregrad. Sofortige Behebung erforderlich."},
			{"NICHT BEWERTET", "Keine Befunde für diesen Artikel erzeugt. Unzureichende Daten zur Bestimmung des Compliance-Status."},
		},

		SecScope:           "Bewertungsumfang und Methodik",
		H2SystemsInScope:   "Systeme im Prüfungsumfang",
		BodySystemsInScope: "Die folgenden Systeme wurden in dieses Sicherheitsassessment einbezogen:",
		H2Methodology:      "Bewertungsmethodik",
		BodyMethodology1: "Dieses Assessment wurde mit dem IAM-Sicherheitsscanner Idenaro durchgeführt. " +
			"Alle Probes sind unauthentifiziert und erfordern keine Zugangsdaten oder Kenntnisse interner " +
			"Systeme. Der Scanner prüft öffentlich erreichbare Identitätsinfrastruktur aus der Perspektive " +
			"eines externen, nicht privilegierten Beobachters.",
		BodyMethodology2: "Durchgeführte Bewertungsaktivitäten:",
		Activities: []string{
			"OIDC / OpenID Connect Konfigurationsanalyse (Discovery-Endpunkte, Algorithmus-Erzwingung, PKCE)",
			"SAML-Metadaten und Assertion-Sicherheitsprüfungen (Signierung, Verschlüsselung, Redirect-Validierung)",
			"Prüfung auf Multi-Faktor-Authentifizierung und Bypass-Resistenz",
			"HTTP-Sicherheits-Header-Enumeration (HSTS, CSP, X-Frame-Options, Referrer-Policy)",
			"TLS-Konfigurationsanalyse (Protokollversionen, Cipher-Suites, Zertifikatsgültigkeit)",
			"Inspektion von Session-Cookie-Sicherheitsattributen (Secure, HttpOnly, SameSite)",
			"Überprüfung der CORS-Richtlinien-Ursprungs-Allowlist",
			"OAuth2 / OIDC-Callback-Endpunkt-State-Parameter-Validierung",
			"Testen der Benutzeraufzählungsresistenz in Authentifizierungsabläufen",
			"Erkennung exponierter Admin- und Debug-Endpunkte",
			"Authentifizierungsprüfungen an SCIM-Bereitstellungsendpunkten",
			"Bewertung von Token-Lebenszyklus- und Widerrufsendpunkten",
			"Token-Validierungsprobing an Relying-Party-Anwendungen",
		},
		H2Limitations: "Scope-Einschränkungen",
		Limitations: []string{
			"Dies ist ein unauthentifiziertes Assessment. Befunde spiegeln ausschließlich die extern beobachtbare Sicherheitslage wider.",
			"Authentifizierte Anwendungsabläufe, interne APIs und Post-Login-Sicherheitskontrollen liegen außerhalb des Scope dieses Assessments.",
			"Token-Validierungsprüfungen mit Bearer-JWT-Probes sind bei Endpunkten mit cookie-basierten Sitzungen nicht aussagekräftig.",
			"Das Fehlen eines Befundes schließt das Vorhandensein einer Schwachstelle nicht aus; nur beobachtbares externes Verhalten wird bewertet.",
			"Dieser Bericht ersetzt keinen vollständigen Penetrationstest oder eine Quellcode-Sicherheitsüberprüfung.",
		},
		H2ComplianceBasis: "Grundlage der Compliance-Zuordnung",
		BodyComplianceBasis: "Alle Befunde sind der NIS2-Richtlinie (EU) 2022/2555, Artikel 21(2), Unterabsätzen " +
			"(a), (d), (e), (g), (h), (i) und (j) zugeordnet. Die Zuordnung basiert auf der technischen " +
			"Natur der Befunde und ihrer Beziehung zu den von jedem Unterabsatz vorgeschriebenen " +
			"Sicherheitsmaßnahmen. Die Unterabsätze (b), (c) und (f) betreffen Incident-Management, " +
			"Business Continuity und Richtlinienbewertung; diese liegen außerhalb des technischen IAM-Assessments.",

		SecArticleAnalysis: "%d. NIS2-Artikel-21-Compliance-Analyse",
		ArticleIntro: "Dieser Abschnitt enthält eine detaillierte Compliance-Bewertung für jeden anwendbaren " +
			"NIS2-Art.-21(2)-Unterabsatz. Identity-Provider-Befunde und Client-Anwendungs-Befunde werden " +
			"separat bewertet. Der Gesamt-Compliance-Status spiegelt das schlechteste Ergebnis beider " +
			"Komponenten wider.",
		H3Controls:    "Identity Provider - Verifizierte Kontrollen",
		NoControls:    "Keine Kontrollen für diesen Artikel im aktuellen Scan verifiziert.",
		H3Violations:  "Identity Provider - Festgestellte Verstöße",
		NoViolations:  "Keine Compliance-Verstöße für diesen Artikel festgestellt.",
		H3Obligations: "Compliance-Verpflichtungen (Anforderungen Art. 21(2))",

		LabelIdpSystems:    "Identity Provider",
		LabelClientSystems: "Client-Anwendungen",
		H3ClientSection:    "Bewertung der Client-Anwendung",
		H3ClientControls:   "Client-Anwendung - Verifizierte Kontrollen",
		H3ClientViolations: "Client-Anwendung - Festgestellte Verstöße",
		NoClientControls:   "Keine Kontrollen für die Client-Anwendung in diesem Artikel verifiziert.",
		NoClientViolations: "Keine Compliance-Verstöße für die Client-Anwendung festgestellt.",
		NoClientScanned:    "Keine Client-Anwendung wurde in diesem Assessment bewertet.",

		SecRemediation: "Maßnahmenplan",
		BodyRemediation: "Die folgende Tabelle listet alle Compliance-Verstöße in Prioritätsreihenfolge auf. " +
			"Kritische und hochgradige Befunde erfordern sofortige Behebung. Mittelschwere Befunde " +
			"müssen innerhalb eines im Risikoregister dokumentierten Maßnahmenplans behoben werden. " +
			"Befunde mit niedrigem Schweregrad sollten im Rahmen der regulären Sicherheitswartung behoben werden.",
		ColNumber:         "#",
		ColSeverity:       "Schweregrad",
		ColFinding:        "Befund",
		ColHost:           "Host",
		NoViolationsFound: "Keine Compliance-Verstöße gefunden. Alle bewerteten Kontrollen sind konform.",
		H2RemTimeline:     "Empfohlener Maßnahmenplan",
		TimelineRows: [4][2]string{
			{"KRITISCHE Befunde:", "Sofort - innerhalb von 24-72 Stunden. CISO informieren. Im Risikoregister als Incident dokumentieren."},
			{"HOHE Befunde:", "Kurzfristig - innerhalb von 14 Tagen. Verantwortlichen benennen, Maßnahmen definieren und bis zur Schließung verfolgen."},
			{"MITTLERE Befunde:", "Mittelfristig - innerhalb von 60 Tagen. In Sprint-Backlog oder nächstes Wartungsfenster aufnehmen."},
			{"NIEDRIGE Befunde:", "Langfristig - innerhalb von 90 Tagen oder dem nächsten Major-Release. Als akzeptiertes Risiko mit dokumentierter Begründung zulässig."},
		},

		SecAppendix: "Anhang A: Vollständige technische Befunde",
		AppendixIntro: "Dieser Anhang enthält alle vom Assessment erzeugten Befunde, einschließlich informativer " +
			"Befunde, die implementierte Kontrollen dokumentieren. Befunde sind nach bewertetem System gruppiert.",
		RiskScoreLabel:    "Risiko-Score: %d / 100",
		NoFindingsForHost: "Keine Befunde für diesen Host.",

		CardRecommendation: "Empfehlung:",
		CardMetaFmt:        "Host: %s  |  Modul: %s  |  Konfidenz: %s",
		CardNIS2Prefix:     "NIS2: ",
	}
}
