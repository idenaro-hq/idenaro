import { useEffect, useState } from "react";
import { GetAppVersion, GetLicenseStatus, GetModules } from "../wailsjs/go/main/App";
import { Quit, WindowMinimise, WindowToggleMaximise } from "../wailsjs/runtime/runtime";
import { main } from "../wailsjs/go/models";
import { Locale, t } from "./i18n";
import { Icon } from "./utils/icons";
import { HelpView } from "./views/HelpView";
import { NIS2View } from "./views/NIS2View";
import { DocsView } from "./views/DocsView";
import { ScanView } from "./views/ScanView";
import { ResultsView } from "./views/ResultsView";
import { SettingsView } from "./views/SettingsView";
import "./App.css";

type View = "scan" | "results" | "settings";

export default function App() {
  const [view, setView]               = useState<View>("scan");
  const [version, setVersion]         = useState("1.0.0");
  const [locale, setLocale]           = useState<Locale>("en");
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [modules, setModules]         = useState<string[]>([]);
  const [selectedModules, setSelectedModules] = useState<Set<string>>(new Set());
  const [skipTLS, setSkipTLS]         = useState(false);
  const [timeoutSec, setTimeoutSec]   = useState(30);
  const [results, setResults]         = useState<main.ScanResultDTO[]>([]);
  const [fontSizePercent, setFontSizePercent] = useState(100);
  const [lightMode, setLightMode]     = useState(false);
  const [showDocs, setShowDocs]       = useState(false);
  const [showNIS2, setShowNIS2]       = useState(false);
  const [showHelp, setShowHelp]       = useState(false);
  const [docsInitialId, setDocsInitialId] = useState<string | undefined>(undefined);
  // This is a fully open-source build: all former "pro" features are always
  // unlocked. Kept as state (rather than a constant) so the props/handlers
  // below did not need to be reshaped; GetLicenseStatus() always reports
  // Licensed:true from the backend as well.
  const [proLicensed, setProLicensed] = useState(true);
  const [licenseEmail, setLicenseEmail] = useState("");
  const [licenseExp, setLicenseExp]   = useState("");

  const appZoom = (fontSizePercent + 30) / 100;

  useEffect(() => {
    void GetAppVersion().then(setVersion).catch(() => {});
    void GetModules().then(list => { setModules(list); setSelectedModules(new Set(list)); }).catch(() => {});
    void GetLicenseStatus().then(s => {
      setProLicensed(s.licensed ?? false);
      setLicenseEmail(s.email ?? "");
      setLicenseExp(s.exp ?? "");
    }).catch(() => {});
  }, []);

  function handleScanComplete(r: main.ScanResultDTO[]) {
    setResults(r);
    setView("results");
  }

  function handleLicenseActivated(email: string, exp: string, mods: string[]) {
    setProLicensed(true);
    setLicenseEmail(email);
    setLicenseExp(exp);
    setModules(mods);
    setSelectedModules(new Set(mods));
  }

  function openDocForFinding(id: string) {
    setDocsInitialId(id);
    setShowDocs(true);
  }

  const titleBar = (
    <header className="window-bar">
      <div className="window-brand">
        <button className="burger-btn" onClick={() => setSidebarOpen(o => !o)} title="Toggle sidebar">
          {Icon.Burger}
        </button>
        <svg className="brand-logo" viewBox="0 0 32 32" fill="none" aria-hidden="true">
          <defs>
            <linearGradient id="brand-g" x1="0" y1="0" x2="32" y2="32" gradientUnits="userSpaceOnUse">
              <stop stopColor="#1e3a8a"/>
              <stop offset="1" stopColor="#2563eb"/>
            </linearGradient>
          </defs>
          <rect width="32" height="32" rx="6.7" fill="url(#brand-g)"/>
          {/* Radar circles */}
          <circle cx="16" cy="8.7" r="5" stroke="#93c5fd" strokeWidth="0.95" strokeOpacity="0.6" fill="none"/>
          <circle cx="16" cy="8.7" r="3" stroke="#bfdbfe" strokeWidth="0.75" strokeOpacity="0.75" fill="none"/>
          {/* Sweep arm */}
          <line x1="16" y1="8.7" x2="19.5" y2="5.1" stroke="white" strokeWidth="1.1" strokeLinecap="round" strokeOpacity="0.95"/>
          {/* i-dot / radar origin */}
          <circle cx="16" cy="8.7" r="1.2" fill="white"/>
          {/* Sweep glow arc */}
          <path d="M 16 3.7 A 5 5 0 0 1 19.5 5.1" stroke="#bfdbfe" strokeWidth="1.5" strokeLinecap="round" strokeOpacity="0.5" fill="none"/>
          {/* i stem */}
          <rect x="13.5" y="14" width="3.8" height="13.5" rx="1.6" fill="white" fillOpacity="0.95"/>
        </svg>
        <span className="brand-name">Idenaro</span>
        <span className="brand-tag">v{version}</span>
      </div>
      <div className="window-controls">
        <button className="topbar-btn" onClick={() => { setShowDocs(false); setShowNIS2(false); setShowHelp(false); setView("settings"); }} title={t(locale, "tbSettings")}>
          {Icon.Gear}<span className="topbar-btn-label">{t(locale, "tbSettings")}</span>
        </button>
        <button className="topbar-btn" onClick={() => setLocale(l => l === "en" ? "de" : "en")} title={t(locale, "settingsLanguage")}>
          {Icon.Globe}<span className="topbar-btn-label">{locale.toUpperCase()}</span>
        </button>
        <button className="topbar-btn" onClick={() => setShowHelp(true)} title={t(locale, "tbHelp")}>
          {Icon.Help}<span className="topbar-btn-label">{t(locale, "tbHelp")}</span>
        </button>
        <div className="topbar-sep"/>
        <button className="window-btn" onClick={() => void WindowMinimise()}>─</button>
        <button className="window-btn" onClick={() => void WindowToggleMaximise()}>▭</button>
        <button className="window-btn close" onClick={() => void Quit()}>✕</button>
      </div>
    </header>
  );

  const overlayShell = (children: React.ReactNode) => (
    <div className="app-shell" style={{zoom: appZoom}}>
      {titleBar}
      <div className="app-body" style={{overflow:"hidden",display:"flex"}}>
        <div style={{flex:1,minHeight:0,overflow:"hidden",display:"flex",flexDirection:"column"}}>
          {children}
        </div>
      </div>
    </div>
  );

  if (showHelp) return overlayShell(<HelpView onBack={() => setShowHelp(false)} locale={locale} />);
  if (showNIS2) return overlayShell(<NIS2View onBack={() => setShowNIS2(false)} locale={locale} />);
  if (showDocs) return overlayShell(
    <DocsView onBack={() => { setShowDocs(false); setDocsInitialId(undefined); }} locale={locale} initialId={docsInitialId} />
  );

  return (
    <div className="app-shell" data-theme={lightMode ? "light" : "dark"} style={{zoom: appZoom}}>
      {titleBar}
      <div className="app-body">
        <aside className={`sidebar ${sidebarOpen ? "" : "collapsed"}`}>
          <div className="sidebar-inner">
            <div className="sidebar-nav">
              <div className="sidebar-group-label">{t(locale, "navScan")}</div>
              <button className={`nav-btn ${view === "scan" ? "active" : ""}`} onClick={() => setView("scan")}>
                {Icon.Search} {t(locale, "navNewScan")}
              </button>
              <div className="sidebar-group-label" style={{marginTop:8}}>{t(locale, "navResults")}</div>
              <button className={`nav-btn ${view === "results" ? "active" : ""}`} onClick={() => setView("results")} disabled={!results.length}>
                {Icon.Check} {t(locale, "navResults")}
                {results.length > 0 && <span style={{marginLeft:"auto",fontFamily:"JetBrains Mono",fontSize:10,color:"var(--accent)"}}>{results.length}</span>}
              </button>
              <div className="sidebar-group-label" style={{marginTop:8}}>{t(locale, "navCompliance")}</div>
              <button
                className="nav-btn"
                onClick={() => proLicensed ? setShowNIS2(true) : setView("settings")}
                title={proLicensed ? undefined : "Pro feature - activate license in Settings"}
              >
                {Icon.NIS2} {t(locale, "navNIS2Guide")}
                {!proLicensed && <span className="pro-badge">PRO</span>}
              </button>
              <div className="sidebar-group-label" style={{marginTop:8}}>{t(locale, "navReference")}</div>
              <button className="nav-btn" onClick={() => { setDocsInitialId(undefined); setShowDocs(true); }}>
                {Icon.Book} {t(locale, "navFindingDocs")}
              </button>
            </div>
            <div className="sidebar-footer">
              IAM assessment<br/>
              NIS2 Art. 21 aligned<br/>
              © Idenaro
            </div>
          </div>
        </aside>

        <main className={`content${lightMode ? " light" : ""}`}>
          {view === "scan" && (
            <ScanView
              locale={locale}
              proLicensed={proLicensed}
              modules={modules}
              selectedModules={selectedModules}
              onModulesChange={setSelectedModules}
              skipTLS={skipTLS}
              onSkipTLSChange={setSkipTLS}
              timeoutSec={timeoutSec}
              onTimeoutChange={setTimeoutSec}
              onScanComplete={handleScanComplete}
              onGoSettings={() => setView("settings")}
            />
          )}
          {view === "results" && (
            <ResultsView
              locale={locale}
              proLicensed={proLicensed}
              results={results}
              selectedModules={selectedModules}
              onResultsChange={updater => setResults(updater)}
              onShowNIS2={() => setShowNIS2(true)}
              onGoSettings={() => setView("settings")}
              onOpenDoc={openDocForFinding}
            />
          )}
          {view === "settings" && (
            <SettingsView
              locale={locale}
              onLocaleChange={setLocale}
              fontSizePercent={fontSizePercent}
              onFontSizeChange={setFontSizePercent}
              lightMode={lightMode}
              onLightModeChange={setLightMode}
              sidebarOpen={sidebarOpen}
              onSidebarToggle={() => setSidebarOpen(o => !o)}
              proLicensed={proLicensed}
              licenseEmail={licenseEmail}
              licenseExp={licenseExp}
              onLicenseActivated={handleLicenseActivated}
            />
          )}
        </main>
      </div>
    </div>
  );
}
