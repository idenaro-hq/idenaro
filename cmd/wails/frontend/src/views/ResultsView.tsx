import { useMemo, useState } from "react";
import { ExportCompliancePDF, ExportHTML, ExportJSON, OpenImportJSON, SaveFile } from "../../wailsjs/go/main/App";
import { main } from "../../wailsjs/go/models";
import { Locale, t } from "../i18n";
import { SEV_ORDER } from "../data/presets";
import { Icon } from "../utils/icons";
import { ScoreGauge, ScoreTooltip } from "../components/ScoreGauge";
import { FindingCard } from "../components/FindingCard";
import { useFindingTranslations } from "../utils/findingTranslations";

type SevFilter = "all" | "critical" | "high" | "medium" | "low" | "info" | "chain";

type Props = {
  locale: Locale;
  proLicensed: boolean;
  results: main.ScanResultDTO[];
  selectedModules: Set<string>;
  onResultsChange: (updater: (prev: main.ScanResultDTO[]) => main.ScanResultDTO[]) => void;
  onShowNIS2: () => void;
  onGoSettings: () => void;
  onOpenDoc: (id: string) => void;
};

export function ResultsView({
  locale, proLicensed, results, selectedModules,
  onResultsChange, onShowNIS2, onGoSettings, onOpenDoc,
}: Props) {
  const [activeResultIndex, setActiveResultIndex] = useState(0);
  const [severityFilter, setSeverityFilter] = useState<SevFilter>("all");
  const [search, setSearch] = useState("");
  const [exportBusy, setExportBusy] = useState<"" | "html" | "json" | "pdf">("");
  const deTexts = useFindingTranslations(locale);

  const activeResult = results[activeResultIndex] ?? null;
  const counts = activeResult?.counts ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0, chain: 0, total: 0 };

  function handleSelectResult(idx: number) {
    setActiveResultIndex(idx);
    setSeverityFilter("all");
    setSearch("");
  }

  const filteredFindings = useMemo(() => {
    if (!activeResult?.findings) return [];
    const q = search.trim().toLowerCase();
    return activeResult.findings
      .filter(f => {
        const s = (f.severity || "").toLowerCase();
        if (severityFilter === "chain")    return f.isChain === true;
        if (severityFilter === "critical") return s === "critical" && !f.isChain;
        if (severityFilter === "high")     return s === "high" && !f.isChain;
        if (severityFilter === "medium")   return s === "medium" && !f.isChain;
        if (severityFilter === "low")      return s === "low" && !f.isChain;
        if (severityFilter === "info")     return s === "info" && !f.isChain;
        return true;
      })
      .filter(f => !q || [f.title, f.description, f.module, f.recommendation, ...(f.nis2Articles ?? [])].join(" ").toLowerCase().includes(q))
      .sort((a, b) => {
        if (a.isChain && !b.isChain) return -1;
        if (!a.isChain && b.isChain) return 1;
        return (SEV_ORDER[a.severity ?? "INFO"] ?? 4) - (SEV_ORDER[b.severity ?? "INFO"] ?? 4);
      });
  }, [activeResult, activeResultIndex, severityFilter, search]);

  async function exportHtml() {
    if (!activeResult || exportBusy) return;
    setExportBusy("html");
    try {
      const c = await ExportHTML([activeResult.host], Array.from(selectedModules));
      await SaveFile(`${activeResult.host}-report.html`, c);
    } finally { setExportBusy(""); }
  }

  async function exportJson() {
    if (!activeResult || exportBusy) return;
    setExportBusy("json");
    try {
      const c = await ExportJSON([activeResult.host], Array.from(selectedModules));
      await SaveFile(`${activeResult.host}-report.json`, c);
    } finally { setExportBusy(""); }
  }

  async function exportCompliancePdf() {
    if (results.length === 0 || exportBusy) return;
    setExportBusy("pdf");
    try {
      await ExportCompliancePDF(JSON.stringify(results), locale);
    } finally { setExportBusy(""); }
  }

  async function importJson() {
    if (exportBusy) return;
    const data = await OpenImportJSON();
    if (!data || data.length === 0) return;
    onResultsChange(prev => {
      const merged = [...prev];
      for (const r of data) {
        const idx = merged.findIndex(x => x.host === r.host);
        if (idx >= 0) merged[idx] = r;
        else merged.push(r);
      }
      return merged;
    });
    setActiveResultIndex(0);
    setSeverityFilter("all");
    setSearch("");
  }

  return (
    <div className="panel">
      <div className="row-between">
        <div className="page-hd">
          <div className="page-title">{t(locale, "resultsTitle")}</div>
          <div className="page-sub">{activeResult?.host || t(locale, "resultsSelectHost")}</div>
        </div>
        <div className="export-row">
          <button className="btn btn-sm" onClick={() => void importJson()} disabled={!!exportBusy}>
            {Icon.Upload} {t(locale, "resultsImportJSON")}
          </button>
          <button
            className="btn btn-sm"
            onClick={() => proLicensed ? onShowNIS2() : onGoSettings()}
            title={proLicensed ? undefined : "Pro feature - activate license in Settings"}
          >
            {Icon.NIS2} {t(locale, "resultsNIS2")}{!proLicensed && <span className="pro-badge">PRO</span>}
          </button>
          <button
            className="btn btn-sm btn-pdf"
            onClick={() => proLicensed ? void exportCompliancePdf() : onGoSettings()}
            disabled={results.length === 0 || !!exportBusy}
            title={proLicensed ? undefined : "Pro feature - activate license in Settings"}
          >
            {exportBusy === "pdf" ? <>{Icon.Spin} {t(locale, "resultsExporting")}</> : <>{Icon.PDF} {t(locale, "resultsExportPDF")}</>}
            {!proLicensed && <span className="pro-badge">PRO</span>}
          </button>
          <button className="btn btn-sm" onClick={() => void exportHtml()} disabled={!activeResult || !!exportBusy}>
            {exportBusy === "html" ? <>{Icon.Spin} {t(locale, "resultsExporting")}</> : <>{Icon.Export} {t(locale, "resultsExportHTML")}</>}
          </button>
          <button className="btn btn-sm" onClick={() => void exportJson()} disabled={!activeResult || !!exportBusy}>
            {exportBusy === "json" ? <>{Icon.Spin} {t(locale, "resultsExporting")}</> : <>{Icon.Code} {t(locale, "resultsExportJSON")}</>}
          </button>
        </div>
      </div>

      {results.length > 0 && (
        <div className="card host-list">
          {results.map((r, idx) => (
            <button key={`${r.host}-${idx}`} className={`host-pill ${idx === activeResultIndex ? "active" : ""}`} onClick={() => handleSelectResult(idx)}>
              <strong>{r.host}</strong>
              <span>{t(locale, "resultsRisk")}: {r.overallScore}/100 · {r.duration}</span>
            </button>
          ))}
        </div>
      )}

      {activeResult && (
        <>
          <div className="card summary-card">
            <div className="score-gauge-wrap">
              <ScoreGauge score={activeResult.overallScore ?? 0} locale={locale} />
              <div style={{display:"flex",alignItems:"center"}}>
                <span className="score-gauge-label">{t(locale, "scoreRisk")}</span>
                <ScoreTooltip score={activeResult.overallScore ?? 0} locale={locale} />
              </div>
            </div>
            <div>
              <div style={{fontFamily:"JetBrains Mono",fontSize:13,fontWeight:600,color:"var(--text)"}}>{activeResult.host}</div>
              <div className="muted" style={{marginTop:2}}>{t(locale, "resultsScannedIn")} {activeResult.duration || "-"}</div>
            </div>
            <div className="count-badges">
              {counts.chain    > 0 && <span className="badge chain"> {counts.chain}</span>}
              {counts.critical > 0 && <span className="badge crit">C {counts.critical}</span>}
              {counts.high     > 0 && <span className="badge high">H {counts.high}</span>}
              {counts.medium   > 0 && <span className="badge med">M {counts.medium}</span>}
              {counts.low      > 0 && <span className="badge low">L {counts.low}</span>}
              {counts.info     > 0 && <span className="badge info">I {counts.info}</span>}
            </div>
          </div>

          <div className="card">
            <div className="filter-row">
              {([
                ["all",      t(locale,"sevAll"),      "fb-all",   counts.total],
                ["critical", t(locale,"sevCritical"), "fb-crit",  counts.critical],
                ["high",     t(locale,"sevHigh"),     "fb-high",  counts.high],
                ["medium",   t(locale,"sevMedium"),   "fb-med",   counts.medium],
                ["low",      t(locale,"sevLow"),      "fb-low",   counts.low],
                ["info",     t(locale,"sevInfo"),     "fb-info",  counts.info],
                ["chain",    t(locale,"sevChain"),    "fb-chain", counts.chain],
              ] as [SevFilter, string, string, number][]).map(([key, label, cls, count]) => (
                <button key={key} className={`filter-btn ${cls} ${severityFilter === key ? "active" : ""}`} onClick={() => setSeverityFilter(key)}>
                  {label} <span className="fcount">{count}</span>
                </button>
              ))}
            </div>
            <input className="search" value={search} onChange={e => setSearch(e.target.value)} placeholder={t(locale, "resultsSearch")}/>
            <div className="findings">
              {filteredFindings.length === 0
                ? <p className="muted">{t(locale, "resultsNoMatch")}</p>
                : filteredFindings.map((f, i) => (
                    <FindingCard key={`${activeResultIndex}-${f.id}-${i}`} f={f} index={i} locale={locale} onOpenDoc={onOpenDoc} deText={deTexts.get(f.id)}/>
                  ))
              }
            </div>
          </div>
        </>
      )}

      {!activeResult && results.length === 0 && (
        <div className="card">
          <p className="muted">{t(locale, "resultsNoResults")}</p>
          <div style={{marginTop:12}}>
            <button className="btn btn-sm" onClick={() => void importJson()}>
              {Icon.Upload} {t(locale, "resultsImportJSON")}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
