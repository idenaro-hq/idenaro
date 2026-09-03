import { Locale, t } from "../i18n";

type Props = {
  locale: Locale;
  onLocaleChange: (l: Locale) => void;
  fontSizePercent: number;
  onFontSizeChange: (v: number) => void;
  lightMode: boolean;
  onLightModeChange: (v: boolean) => void;
  sidebarOpen: boolean;
  onSidebarToggle: () => void;
  // Kept for prop-shape compatibility with App.tsx; this build has no
  // license gating so these are always the "unlocked" values.
  proLicensed: boolean;
  licenseEmail: string;
  licenseExp: string;
  onLicenseActivated: (email: string, exp: string, modules: string[]) => void;
};

export function SettingsView({
  locale, onLocaleChange,
  fontSizePercent, onFontSizeChange,
  lightMode, onLightModeChange,
  sidebarOpen, onSidebarToggle,
}: Props) {
  return (
    <div className="panel">
      <div className="page-hd"><div className="page-title">{t(locale, "settingsTitle")}</div></div>

      <div className="card">
        <div className="card-hd"><span className="label-sm">{t(locale, "settingsDisplay")}</span></div>
        <div className="settings-row">
          <div>
            <div className="settings-label">{t(locale, "settingsScale")}</div>
            <div className="settings-desc">{t(locale, "settingsScaleDesc")}</div>
          </div>
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <button className="btn btn-sm" onClick={() => onFontSizeChange(Math.max(fontSizePercent - 7, 70))}>−</button>
            <span style={{fontFamily:"JetBrains Mono",fontSize:12,minWidth:34,textAlign:"center"}}>{fontSizePercent}%</span>
            <button className="btn btn-sm" onClick={() => onFontSizeChange(Math.min(fontSizePercent + 7, 150))}>+</button>
            <button className="btn btn-sm" onClick={() => onFontSizeChange(100)}>{t(locale, "settingsReset")}</button>
          </div>
        </div>
        <div className="settings-row">
          <div>
            <div className="settings-label">{t(locale, "settingsTheme")}</div>
            <div className="settings-desc">{t(locale, "settingsThemeDesc")}</div>
          </div>
          <label className="switch">
            <input type="checkbox" checked={lightMode} onChange={e => onLightModeChange(e.target.checked)} />
            <span className="sw-track"/>
            {lightMode ? t(locale, "settingsLight") : t(locale, "settingsDark")}
          </label>
        </div>
        <div className="settings-row">
          <div>
            <div className="settings-label">{t(locale, "settingsSidebar")}</div>
            <div className="settings-desc">{t(locale, "settingsSidebarDesc")}</div>
          </div>
          <button className="btn btn-sm" onClick={onSidebarToggle}>
            {sidebarOpen ? t(locale, "settingsCollapse") : t(locale, "settingsExpand")}
          </button>
        </div>
        <div className="settings-row">
          <div>
            <div className="settings-label">{t(locale, "settingsLanguage")}</div>
            <div className="settings-desc">{t(locale, "settingsLanguageDesc")}</div>
          </div>
          <div style={{display:"flex",gap:6}}>
            <button className={`btn btn-sm${locale === "en" ? " btn-primary" : ""}`} onClick={() => onLocaleChange("en")}>EN</button>
            <button className={`btn btn-sm${locale === "de" ? " btn-primary" : ""}`} onClick={() => onLocaleChange("de")}>DE</button>
          </div>
        </div>
      </div>

      <div className="card" style={{marginTop:12}}>
        <div className="card-hd"><span className="label-sm">{locale === "de" ? "Lizenz" : "License"}</span></div>
        <div className="settings-row" style={{borderBottom:"none"}}>
          <div>
            <div className="settings-label" style={{color:"var(--c-low)"}}>
              ✓ {locale === "de"
                ? "Alle Funktionen freigeschaltet - keine Lizenz erforderlich"
                : "All features unlocked - no license required"}
            </div>
            <div className="settings-desc" style={{marginTop:2}}>
              {locale === "de"
                ? "Dies ist eine vollständig quelloffene Version, die alle ehemaligen Free- und Pro-Module enthält."
                : "This is a fully open-source build that includes all former free and pro modules."}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
