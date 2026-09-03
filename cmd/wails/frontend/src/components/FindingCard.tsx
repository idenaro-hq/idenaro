import { useState } from "react";
import { main } from "../../wailsjs/go/models";
import { Locale, t } from "../i18n";
import { Icon } from "../utils/icons";
import type { FindingTexts } from "../utils/findingTranslations";

type Props = {
  f: main.FindingDTO;
  index: number;
  locale: Locale;
  onOpenDoc: (id: string) => void;
  deText?: FindingTexts;
};

export function FindingCard({ f, index, locale, onOpenDoc, deText }: Props) {
  const [open, setOpen] = useState(false);
  const sev = f.isChain ? "CHAIN" : (f.severity || "INFO");
  const description    = deText?.description    || f.description;
  const recommendation = deText?.recommendation || f.recommendation;
  return (
    <article className="finding" data-sev={sev} style={{animationDelay:`${Math.min(index*20,200)}ms`}}>
      <button className="finding-hd" onClick={() => setOpen(o => !o)}>
        <div className="finding-hd-left">
          <span className={`sev-badge sev-${sev}`}>{f.isChain ? "CHAIN" : sev}</span>
          <span className="finding-title">{f.title}</span>
        </div>
        <div className="finding-hd-right">
          <span className="mod-tag">{f.module}</span>
          <span className="risk-num">{f.riskScore}</span>
          <button className="finding-doc-btn" title={t(locale, "tbHelp")} onClick={e => { e.stopPropagation(); onOpenDoc(f.id); }}>{Icon.Help}</button>
          <span className="chevron">{open ? "▲" : "▼"}</span>
        </div>
      </button>
      {open && (
        <div className="finding-body fade-in">
          <p className="finding-desc">{description}</p>
          {f.evidence?.length > 0 && (
            <div className="fsect">
              <div className="fsect-label">{t(locale, "findingEvidence")}</div>
              {f.evidence.map((e: string, i: number) => <div key={i} className="evidence-item">{e}</div>)}
            </div>
          )}
          {recommendation && (
            <div className="fsect">
              <div className="fsect-label">{t(locale, "findingRecommendation")}</div>
              <div className="rec-text">{recommendation}</div>
            </div>
          )}
          {f.nis2Articles?.length > 0 && (
            <div className="fsect">
              <div className="fsect-label">{t(locale, "findingNIS2Mapping")}</div>
              <div className="nis2-tags">{f.nis2Articles.map((a: string, i: number) => <span key={i} className="nis2-tag">{a}</span>)}</div>
            </div>
          )}
          <div className="fmeta-row">
            <span>{t(locale, "findingConfidence")}: <strong>{f.confidence}</strong></span>
            <span>{t(locale, "findingScore")}: <strong>{f.riskScore}</strong></span>
            <span>{t(locale, "findingModule")}: <strong>{f.module}</strong></span>
          </div>
        </div>
      )}
    </article>
  );
}
