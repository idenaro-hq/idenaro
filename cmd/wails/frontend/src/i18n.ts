export type Locale = "en" | "de";

type Strings = {
  // navigation
  navScan: string;
  navNewScan: string;
  navResults: string;
  navCompliance: string;
  navNIS2Guide: string;
  navReference: string;
  navFindingDocs: string;

  // title bar
  tbSettings: string;
  tbHelp: string;

  // scan view
  scanTitle: string;
  scanSub: string;
  scanIdpTargets: string;
  scanIdpHint: string;
  scanPlaceholder: string;
  scanAnotherTarget: string;
  scanFieldHint: string;
  scanClientSection: string;
  scanClientSub: string;
  scanClientPlaceholder: string;
  scanClientAnotherTarget: string;
  scanClientFieldHint: string;
  scanPresets: string;
  scanModules: string;
  scanSelectAll: string;
  scanDeselectAll: string;
  scanOptions: string;
  scanSkipTLS: string;
  scanTimeout: string;
  scanStart: string;
  scanScanning: string;
  scanClientScanning: string;
  scanCancel: string;
  scanProgress: string;

  // results view
  resultsTitle: string;
  resultsSelectHost: string;
  resultsRisk: string;
  resultsScannedIn: string;
  resultsNoMatch: string;
  resultsNoResults: string;
  resultsRunFirst: string;
  resultsSearch: string;
  resultsExportHTML: string;
  resultsExportJSON: string;
  resultsExportPDF: string;
  resultsExporting: string;
  resultsImportJSON: string;
  resultsDocs: string;
  resultsNIS2: string;

  // severity labels
  sevAll: string;
  sevCritical: string;
  sevHigh: string;
  sevMedium: string;
  sevLow: string;
  sevInfo: string;
  sevChain: string;

  // finding detail
  findingEvidence: string;
  findingRecommendation: string;
  findingNIS2Mapping: string;
  findingConfidence: string;
  findingScore: string;
  findingModule: string;

  // score labels
  scoreRisk: string;
  scoreLabel: string;
  scoreCritical: string;
  scoreAtRisk: string;
  scoreModerate: string;
  scoreSecure: string;
  scoreExplain1: string;
  scoreExplain2: string;
  scoreExplain3: string;

  // settings view
  settingsTitle: string;
  settingsDisplay: string;
  settingsScale: string;
  settingsScaleDesc: string;
  settingsTheme: string;
  settingsThemeDesc: string;
  settingsLight: string;
  settingsDark: string;
  settingsSidebar: string;
  settingsSidebarDesc: string;
  settingsCollapse: string;
  settingsExpand: string;
  settingsLanguage: string;
  settingsLanguageDesc: string;
  settingsReset: string;

  // docs / nis2
  docsTitle: string;
  docsFindings: string;
  docsLoading: string;
  docsNotFound: string;
  docsBack: string;
  nis2Title: string;
  nis2Articles: string;
  nis2TagsLabel: string;

  // footer
  footerLine1: string;
};

const en: Strings = {
  navScan: "Scan",
  navNewScan: "New Scan",
  navResults: "Results",
  navCompliance: "Compliance",
  navNIS2Guide: "NIS2 Guide",
  navReference: "Reference",
  navFindingDocs: "Finding Docs",

  tbSettings: "Settings",
  tbHelp: "Help",

  scanTitle: "New Scan",
  scanSub: "IAM misconfiguration assessment",
  scanIdpTargets: "Identity Provider Targets",
  scanIdpHint: "Identity provider or authorization server (Keycloak, ADFS, Okta, Entra ID…)",
  scanPlaceholder: "auth.example.com or host:port - Enter to add ",
  scanAnotherTarget: "Add another IdP…",
  scanFieldHint: "Press Enter or Space after each hostname. Supports host, host:port, https://host",
  scanClientSection: "Client Application Target",
  scanClientSub: "Relying party application - probed for token validation, CORS, and session issues. Leave empty to skip.",
  scanClientPlaceholder: "app.example.com - the relying party URL",
  scanClientAnotherTarget: "Add another client app…",
  scanClientFieldHint: "The web application that consumes the IdP. Append a path to pin the protected endpoint - e.g. https://app.example.com/oauth2/auth for nginx auth_request setups.",
  scanPresets: "Quick Presets",
  scanModules: "IdP Scan Modules",
  scanSelectAll: "Select all",
  scanDeselectAll: "Deselect all",
  scanOptions: "Options",
  scanSkipTLS: "Skip TLS verification",
  scanTimeout: "Timeout",
  scanStart: "Start Scan",
  scanScanning: "Scanning IdP…",
  scanClientScanning: "Scanning client app…",
  scanCancel: "Cancel",
  scanProgress: "Progress",

  resultsTitle: "Results",
  resultsSelectHost: "Select a host",
  resultsRisk: "Risk",
  resultsScannedIn: "Scanned in",
  resultsNoMatch: "No findings match current filters.",
  resultsNoResults: "No results yet. Run a scan from New Scan.",
  resultsRunFirst: "No results yet.",
  resultsSearch: "Search findings…",
  resultsExportHTML: "HTML",
  resultsExportJSON: "JSON",
  resultsExportPDF: "Compliance PDF",
  resultsExporting: "Generating report…",
  resultsImportJSON: "Import JSON",
  resultsDocs: "Docs",
  resultsNIS2: "NIS2",

  sevAll: "All",
  sevCritical: "Critical",
  sevHigh: "High",
  sevMedium: "Medium",
  sevLow: "Low",
  sevInfo: "Info",
  sevChain: "Chain",

  findingEvidence: "Evidence",
  findingRecommendation: "Recommendation",
  findingNIS2Mapping: "NIS2 Mapping",
  findingConfidence: "Confidence",
  findingScore: "Score",
  findingModule: "Module",

  scoreRisk: "Risk Score",
  scoreLabel: "RISK SCORE",
  scoreCritical: "CRITICAL",
  scoreAtRisk: "AT RISK",
  scoreModerate: "MODERATE",
  scoreSecure: "SECURE",
  scoreExplain1: "0 = no findings, no danger.",
  scoreExplain2: "100 = maximum risk across all categories.",
  scoreExplain3: "Critical risk. Immediate remediation required.",

  settingsTitle: "Settings",
  settingsDisplay: "Display",
  settingsScale: "Interface Scale",
  settingsScaleDesc: "Adjusts the overall UI size (70-150%)",
  settingsTheme: "Content Theme",
  settingsThemeDesc: "Switch the main content area between dark and light mode",
  settingsLight: "Light",
  settingsDark: "Dark",
  settingsSidebar: "Sidebar",
  settingsSidebarDesc: "Toggle via burger menu (≡) in title bar",
  settingsCollapse: "Collapse",
  settingsExpand: "Expand",
  settingsLanguage: "Language",
  settingsLanguageDesc: "Switch the interface language",
  settingsReset: "Reset",

  docsTitle: "Finding Reference",
  docsFindings: "Finding Reference",
  docsLoading: "Loading…",
  docsNotFound: "Documentation not found.",
  docsBack: "← Back",
  nis2Title: "NIS2 Compliance",
  nis2Articles: "NIS2 Articles",
  nis2TagsLabel: "Tags mapped to this article",

  footerLine1: "Idenaro - IAM Assessment",
};

const de: Strings = {
  navScan: "Scan",
  navNewScan: "Neuer Scan",
  navResults: "Ergebnisse",
  navCompliance: "Compliance",
  navNIS2Guide: "NIS2-Leitfaden",
  navReference: "Referenz",
  navFindingDocs: "Befund-Referenz",

  tbSettings: "Einstellungen",
  tbHelp: "Hilfe",

  scanTitle: "Neuer Scan",
  scanSub: "IAM-Fehlkonfigurationsprüfung",
  scanIdpTargets: "IdP / Identity-Provider-Ziele",
  scanIdpHint: "Identity Provider oder Autorisierungsserver (Keycloak, ADFS, Okta, Entra ID…)",
  scanPlaceholder: "auth.beispiel.de oder Host:Port - Enter zum Hinzufügen",
  scanAnotherTarget: "Weiteres IdP-Ziel…",
  scanFieldHint: "Nach jedem Hostnamen Enter oder Leertaste drücken. Unterstützt Host, Host:Port, https://Host",
  scanClientSection: "Client-Anwendungsziel",
  scanClientSub: "Relying Party - wird auf Token-Validierung, CORS und Session-Konfiguration geprüft. Leer lassen zum Überspringen.",
  scanClientPlaceholder: "app.beispiel.de - die Relying-Party-URL",
  scanClientAnotherTarget: "Weitere Client-App…",
  scanClientFieldHint: "Die Webanwendung, die den IdP verwendet. Pfad anhängen, um den geschützten Endpunkt festzulegen - z. B. https://app.beispiel.de/oauth2/auth für nginx-auth_request-Setups.",
  scanPresets: "Schnellvorlagen",
  scanModules: "IdP-Scan-Module",
  scanSelectAll: "Alle auswählen",
  scanDeselectAll: "Alle abwählen",
  scanOptions: "Optionen",
  scanSkipTLS: "TLS-Verifizierung überspringen",
  scanTimeout: "Zeitlimit",
  scanStart: "Scan starten",
  scanScanning: "IdP wird gescannt…",
  scanClientScanning: "Client-App wird gescannt…",
  scanCancel: "Abbrechen",
  scanProgress: "Fortschritt",

  resultsTitle: "Ergebnisse",
  resultsSelectHost: "Host auswählen",
  resultsRisk: "Risiko",
  resultsScannedIn: "Gescannt in",
  resultsNoMatch: "Keine Befunde entsprechen den aktuellen Filtern.",
  resultsNoResults: "Noch keine Ergebnisse. Scan über 'Neuer Scan' starten.",
  resultsRunFirst: "Noch keine Ergebnisse.",
  resultsSearch: "Befunde durchsuchen…",
  resultsExportHTML: "HTML",
  resultsExportJSON: "JSON",
  resultsExportPDF: "Compliance PDF",
  resultsExporting: "Bericht wird erstellt…",
  resultsImportJSON: "JSON importieren",
  resultsDocs: "Docs",
  resultsNIS2: "NIS2",

  sevAll: "Alle",
  sevCritical: "Kritisch",
  sevHigh: "Hoch",
  sevMedium: "Mittel",
  sevLow: "Niedrig",
  sevInfo: "Info",
  sevChain: "Kette",

  findingEvidence: "Belege",
  findingRecommendation: "Empfehlung",
  findingNIS2Mapping: "NIS2-Zuordnung",
  findingConfidence: "Konfidenz",
  findingScore: "Score",
  findingModule: "Modul",

  scoreRisk: "Risiko-Score",
  scoreLabel: "RISIKO-SCORE",
  scoreCritical: "KRITISCH",
  scoreAtRisk: "GEFÄHRDET",
  scoreModerate: "MODERAT",
  scoreSecure: "SICHER",
  scoreExplain1: "0 = keine Befunde, kein Risiko.",
  scoreExplain2: "100 = maximales Risiko in allen Kategorien.",
  scoreExplain3: "Kritisches Risiko. Sofortige Behebung erforderlich.",

  settingsTitle: "Einstellungen",
  settingsDisplay: "Anzeige",
  settingsScale: "Oberflächenskalierung",
  settingsScaleDesc: "Passt die Gesamtgröße der Benutzeroberfläche an (70-150 %)",
  settingsTheme: "Inhaltsthema",
  settingsThemeDesc: "Wechselt den Hauptinhaltsbereich zwischen Dunkel- und Hellmodus",
  settingsLight: "Hell",
  settingsDark: "Dunkel",
  settingsSidebar: "Seitenleiste",
  settingsSidebarDesc: "Umschalten über das Burger-Menü (≡) in der Titelleiste",
  settingsCollapse: "Einklappen",
  settingsExpand: "Ausklappen",
  settingsLanguage: "Sprache",
  settingsLanguageDesc: "Sprache der Benutzeroberfläche wechseln",
  settingsReset: "Zurücksetzen",

  docsTitle: "Befund-Referenz",
  docsFindings: "Befund-Referenz",
  docsLoading: "Wird geladen…",
  docsNotFound: "Dokumentation nicht gefunden.",
  docsBack: "← Zurück",
  nis2Title: "NIS2-Compliance",
  nis2Articles: "NIS2-Artikel",
  nis2TagsLabel: "Tags für diesen Artikel",

  footerLine1: "Idenaro - IAM-Analyse",
};

export const translations: Record<Locale, Strings> = { en, de };

export function t(locale: Locale, key: keyof Strings): string {
  return translations[locale][key];
}
