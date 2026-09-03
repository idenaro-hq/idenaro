import { useEffect, useMemo, useState } from "react";
import { CancelScan, RunClientScan, RunScan } from "../../wailsjs/go/main/App";
import { EventsOn } from "../../wailsjs/runtime/runtime";
import { main } from "../../wailsjs/go/models";
import { Locale, t } from "../i18n";
import { PRESETS, PRO_MODULES, isProPreset } from "../data/presets";
import { Icon } from "../utils/icons";
import { InfoTip } from "../components/InfoTip";

type ProgressEvent = { host: string; module: string; done: number; total: number };

type Props = {
  locale: Locale;
  proLicensed: boolean;
  modules: string[];
  selectedModules: Set<string>;
  onModulesChange: (v: Set<string>) => void;
  skipTLS: boolean;
  onSkipTLSChange: (v: boolean) => void;
  timeoutSec: number;
  onTimeoutChange: (v: number) => void;
  onScanComplete: (results: main.ScanResultDTO[]) => void;
  onGoSettings: () => void;
};

export function ScanView({
  locale, proLicensed, modules, selectedModules, onModulesChange,
  skipTLS, onSkipTLSChange, timeoutSec, onTimeoutChange,
  onScanComplete, onGoSettings,
}: Props) {
  const [targets, setTargets] = useState<string[]>([]);
  const [targetInput, setTargetInput] = useState("");
  const [clientTargets, setClientTargets] = useState<string[]>([]);
  const [clientTargetInput, setClientTargetInput] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [isClientScanning, setIsClientScanning] = useState(false);
  const [progressDone, setProgressDone] = useState(0);
  const [progressTotal, setProgressTotal] = useState(0);

  useEffect(() => {
    const off1 = EventsOn("scan:module:done", (p: ProgressEvent) => {
      if (p) { setProgressDone(p.done ?? 0); setProgressTotal(p.total ?? 0); }
    });
    const off2 = EventsOn("scan:started", (p: { total: number }) => {
      setProgressDone(0); setProgressTotal(p?.total ?? 0); setIsScanning(true);
    });
    const off3 = EventsOn("scan:complete", () => setIsScanning(false));
    return () => { off1(); off2(); off3(); };
  }, []);

  const progressPct = progressTotal > 0 ? Math.min(100, Math.round((progressDone / progressTotal) * 100)) : 0;

  const activePresetLabel = useMemo(() => {
    if (modules.length > 0 && selectedModules.size === modules.length) return "Full scan";
    for (const [label, preset] of Object.entries(PRESETS)) {
      if (preset.length > 0 && preset.length === selectedModules.size && preset.every(m => selectedModules.has(m))) return label;
    }
    return "";
  }, [modules.length, selectedModules]);

  function addTargets() {
    const incoming = targetInput.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
    if (!incoming.length) return;
    setTargets(prev => Array.from(new Set([...prev, ...incoming])));
    setTargetInput("");
  }

  function addClientTargets() {
    const incoming = clientTargetInput.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
    if (!incoming.length) return;
    setClientTargets(prev => Array.from(new Set([...prev, ...incoming])));
    setClientTargetInput("");
  }

  function applyPreset(label: string) {
    const preset = PRESETS[label];
    if (!preset || preset.length === 0) { onModulesChange(new Set(modules)); return; }
    onModulesChange(new Set(preset));
  }

  async function runScan() {
    const finalIdpTargets    = targets.length > 0       ? targets       : targetInput.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
    const finalClientTargets = clientTargets.length > 0 ? clientTargets : clientTargetInput.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
    if ((!finalIdpTargets.length && !finalClientTargets.length) || isScanning) return;
    setIsScanning(true); setProgressDone(0); setProgressTotal(0);
    const idpTotal = selectedModules.size * finalIdpTargets.length;
    const allResults: main.ScanResultDTO[] = [];
    try {
      if (finalIdpTargets.length > 0) {
        const data = await RunScan(finalIdpTargets, Array.from(selectedModules), skipTLS, timeoutSec, finalClientTargets.length, locale);
        allResults.push(...(data || []));
      }
      if (finalClientTargets.length > 0) {
        setIsClientScanning(true);
        const data = await RunClientScan(finalClientTargets, skipTLS, timeoutSec, idpTotal, idpTotal + finalClientTargets.length, locale);
        allResults.push(...(data || []));
      }
      onScanComplete(allResults);
    } finally {
      setIsScanning(false);
      setIsClientScanning(false);
    }
  }

  const canScan = !isScanning && (targets.length > 0 || clientTargets.length > 0 || targetInput.trim() !== "" || clientTargetInput.trim() !== "");

  return (
    <div className="panel">
      <div className="page-hd">
        <div className="page-title">{t(locale, "scanTitle")}</div>
        <div className="page-sub">{t(locale, "scanSub")}</div>
      </div>

      <div className="card">
        <div className="card-hd">
          <div style={{display:"flex",alignItems:"center",gap:5}}>
            <span className="label-sm">{t(locale, "scanIdpTargets")}</span>
            <InfoTip text={`${t(locale, "scanIdpHint")}\n\n${t(locale, "scanFieldHint")}`} />
          </div>
        </div>
        <div className="target-area">
          {targets.map(target => (
            <button key={target} className="chip" onClick={() => setTargets(p => p.filter(x => x !== target))}>
              {target} <span style={{opacity:0.6}}>×</span>
            </button>
          ))}
          <input
            value={targetInput}
            onChange={e => setTargetInput(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); addTargets(); } }}
            onBlur={addTargets}
            placeholder={targets.length === 0 ? t(locale, "scanPlaceholder") : t(locale, "scanAnotherTarget")}
            autoFocus
          />
        </div>
      </div>

      <div className="card">
        <div className="card-hd">
          <div style={{display:"flex",alignItems:"center",gap:6}}>
            <span className="label-sm">{t(locale, "scanClientSection")}</span>
            <InfoTip text={`${t(locale, "scanClientSub")}\n\n${t(locale, "scanClientFieldHint")}`} />
            {proLicensed
              ? <span className="tier-badge tier-badge-pro">PRO</span>
              : <span className="tier-badge tier-badge-free" title="Activate a Pro license in Settings for deeper client checks (clickjacking, CSP quality, silent auth probe)">FREE</span>
            }
          </div>
        </div>
        <div className="target-area">
          {clientTargets.map(target => (
            <button key={target} className="chip chip-client" onClick={() => setClientTargets(p => p.filter(x => x !== target))}>
              {target} <span style={{opacity:0.6}}>×</span>
            </button>
          ))}
          <input
            value={clientTargetInput}
            onChange={e => setClientTargetInput(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); addClientTargets(); } }}
            onBlur={addClientTargets}
            placeholder={clientTargets.length === 0 ? t(locale, "scanClientPlaceholder") : t(locale, "scanClientAnotherTarget")}
          />
        </div>
      </div>

      <div className="card">
        <div className="card-hd"><span className="label-sm">{t(locale, "scanPresets")}</span></div>
        <div className="preset-row">
          {Object.keys(PRESETS).map(label => {
            const locked = !proLicensed && isProPreset(label);
            return (
              <button
                key={label}
                className={`preset-btn ${activePresetLabel === label ? "active" : ""} ${locked ? "preset-btn-locked" : ""}`}
                onClick={() => locked ? onGoSettings() : applyPreset(label)}
                title={locked ? "Pro feature - activate license in Settings" : undefined}
              >
                {locked && Icon.Lock} {label}
              </button>
            );
          })}
        </div>
      </div>

      <div className="card">
        <div className="card-hd">
          <span className="label-sm">{t(locale, "scanModules")}</span>
          <button className="link-btn" onClick={() => onModulesChange(selectedModules.size === modules.length ? new Set() : new Set(modules))}>
            {selectedModules.size === modules.length ? t(locale, "scanDeselectAll") : t(locale, "scanSelectAll")}
          </button>
        </div>
        <div className="module-grid">
          {modules.map(m => (
            <label key={m} className={`module-item ${selectedModules.has(m) ? "on" : ""}`}>
              <input
                type="checkbox"
                checked={selectedModules.has(m)}
                onChange={() => { const n = new Set(selectedModules); n.has(m) ? n.delete(m) : n.add(m); onModulesChange(n); }}
              />
              <span>{m}</span>
            </label>
          ))}
          {PRO_MODULES.filter(m => !modules.includes(m)).map(m => (
            <div
              key={m}
              className="module-item module-item-locked"
              title="Pro feature - click to activate license"
              onClick={onGoSettings}
            >
              {Icon.Lock}<span>{m}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <div className="card-hd"><span className="label-sm">{t(locale, "scanOptions")}</span></div>
        <div className="options-row">
          <label className="switch">
            <input type="checkbox" checked={skipTLS} onChange={e => onSkipTLSChange(e.target.checked)} />
            <span className="sw-track"/>
            {t(locale, "scanSkipTLS")}
          </label>
          <div className="slider-wrap">
            <span>{t(locale, "scanTimeout")}</span>
            <input type="range" min={10} max={120} value={timeoutSec} onChange={e => onTimeoutChange(Number(e.target.value))} />
            <strong>{timeoutSec}s</strong>
          </div>
        </div>
      </div>

      <div style={{display:"flex",gap:10,alignItems:"center"}}>
        <button className="btn btn-primary" onClick={() => void runScan()} disabled={!canScan}>
          {isClientScanning
            ? <>{Icon.Spin} {t(locale, "scanClientScanning")}</>
            : isScanning
            ? <>{Icon.Spin} {t(locale, "scanScanning")}</>
            : <>{Icon.Play} {t(locale, "scanStart")}</>
          }
        </button>
        {isScanning && <button className="btn btn-danger btn-sm" onClick={() => void CancelScan()}>{t(locale, "scanCancel")}</button>}
      </div>

      {(isScanning || progressTotal > 0) && (
        <div className="progress-wrap">
          <div className="progress-meta">
            <span>{t(locale, "scanProgress")}</span>
            <span>{progressDone} / {progressTotal} ({progressPct}%)</span>
          </div>
          <div className="progress-bar"><div className="progress-fill" style={{width:`${progressPct}%`}}/></div>
        </div>
      )}
    </div>
  );
}
