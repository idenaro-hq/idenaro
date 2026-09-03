import { useEffect, useState } from "react";
import { GetDocContent } from "../../wailsjs/go/main/App";
import { Locale, t } from "../i18n";
import { DOC_ENTRIES, DOC_GROUPS, GROUP_FILE } from "../data/docs";
import { renderMarkdown, parseGroupedMd } from "../utils/markdown";

export type DocPage = { kind: "index" } | { kind: "module"; group: string } | { kind: "finding"; id: string };

type Props = { onBack: () => void; locale: Locale; initialId?: string };

export function DocsView({ onBack, locale, initialId }: Props) {
  const [activePage, setActivePage] = useState<DocPage>(
    initialId ? { kind: "finding", id: initialId } : { kind: "index" }
  );
  const [groupCache, setGroupCache] = useState<Record<string, Record<string, string>>>({});

  const fileKeyFor = (group: string) => GROUP_FILE[group] ?? group.toLowerCase().replace(/[^a-z0-9]/g, "");

  const groupForPage = (page: DocPage): string => {
    if (page.kind === "module") return page.group;
    if (page.kind === "finding") return DOC_ENTRIES.find(e => e.id === page.id)?.group ?? "";
    return "";
  };

  const fileKey = fileKeyFor(groupForPage(activePage));
  const cacheKey = `${locale}/${fileKey}`;

  useEffect(() => {
    if (!fileKey || cacheKey in groupCache) return;
    const localePath = locale === "de" ? `modules/${fileKey}-de` : `modules/${fileKey}`;
    void GetDocContent(localePath).then(md => {
      if (md) {
        setGroupCache(prev => ({ ...prev, [cacheKey]: parseGroupedMd(md) }));
      } else {
        // fall back to English
        void GetDocContent(`modules/${fileKey}`).then(mdEn => {
          setGroupCache(prev => ({ ...prev, [cacheKey]: parseGroupedMd(mdEn) }));
        }).catch(() => {
          setGroupCache(prev => ({ ...prev, [cacheKey]: {} }));
        });
      }
    }).catch(() => {
      setGroupCache(prev => ({ ...prev, [cacheKey]: {} }));
    });
  }, [cacheKey]);

  function navFinding(id: string) { setActivePage({ kind: "finding", id }); }
  function navModule(group: string) { setActivePage({ kind: "module", group }); }

  const isLoading = !!fileKey && !(cacheKey in groupCache);
  const activeEntry = activePage.kind === "finding"
    ? (DOC_ENTRIES.find(e => e.id === activePage.id) ?? DOC_ENTRIES[0])
    : null;

  let content: React.ReactNode;

  if (activePage.kind === "index") {
    content = (
      <div className="doc-article">
        <h2 style={{fontSize:20,fontWeight:700,marginBottom:14}}>{t(locale, "docsFindings")}</h2>
        <div className="doc-divider"/>
        {DOC_GROUPS.map(group => {
          const entries = DOC_ENTRIES.filter(e => e.group === group);
          return (
            <div key={group} className="doc-index-module">
              <button className="doc-index-module-hd" onClick={() => navModule(group)}>
                <span>{group}</span>
                <span className="doc-index-count">{entries.length}</span>
              </button>
              <div className="doc-index-findings">
                {entries.map(e => (
                  <button key={e.id} className="doc-index-finding-row" onClick={() => navFinding(e.id)}>
                    {e.severity && <span className={`sev-badge sev-${e.severity}`} style={{fontSize:9,padding:"1px 5px",lineHeight:"14px",flexShrink:0}}>{e.severity}</span>}
                    <span>{e.title}</span>
                  </button>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    );
  } else if (activePage.kind === "module") {
    const fk = fileKeyFor(activePage.group);
    const body = groupCache[`${locale}/${fk}`]?.[`${fk}-overview`] ?? "";
    const entries = DOC_ENTRIES.filter(e => e.group === activePage.group);
    content = (
      <div className="doc-article" key={activePage.group}>
        <h2>{activePage.group}</h2>
        <div className="muted" style={{marginBottom:12,fontSize:11}}>
          {entries.length} {locale === "de" ? "Befunde" : "findings"}
        </div>
        <div className="doc-divider"/>
        {isLoading
          ? <p className="muted">{t(locale, "docsLoading")}</p>
          : body
          ? renderMarkdown(body)
          : <p className="muted">{t(locale, "docsNotFound")}</p>
        }
      </div>
    );
  } else if (activeEntry) {
    const fk = fileKeyFor(activeEntry.group);
    const body = groupCache[`${locale}/${fk}`]?.[activeEntry.id] ?? "";
    content = (
      <div className="doc-article" key={activeEntry.id}>
        <div className="doc-sev-row">
          <h2>{activeEntry.title}</h2>
          {activeEntry.severity && <span className={`sev-badge sev-${activeEntry.severity}`}>{activeEntry.severity}</span>}
        </div>
        <div className="muted" style={{marginBottom:12,fontSize:10}}>
          <button className="link-btn" style={{fontSize:10}} onClick={() => navModule(activeEntry.group)}>{activeEntry.group}</button>
        </div>
        <div className="doc-divider"/>
        {isLoading
          ? <p className="muted">{t(locale, "docsLoading")}</p>
          : body
          ? renderMarkdown(body)
          : <p className="muted">{t(locale, "docsNotFound")}</p>
        }
      </div>
    );
  }

  return (
    <div className="doc-layout" style={{flex:1}}>
      <div className="doc-toc">
        <div className="doc-toc-sticky">
          <button className="doc-toc-back" onClick={onBack}>{t(locale, "docsBack")}</button>
        </div>
        <button
          className={`doc-toc-item doc-toc-index-btn ${activePage.kind === "index" ? "active" : ""}`}
          onClick={() => setActivePage({ kind: "index" })}
        >
          {t(locale, "docsFindings")}
        </button>
        {DOC_GROUPS.map(group => (
          <div key={group} className="doc-toc-group-wrap">
            <button
              className={`doc-toc-module ${activePage.kind === "module" && activePage.group === group ? "active" : ""}`}
              onClick={() => navModule(group)}
            >
              {group}
            </button>
            {DOC_ENTRIES.filter(e => e.group === group).map(e => (
              <button
                key={e.id}
                className={`doc-toc-item ${activePage.kind === "finding" && activePage.id === e.id ? "active" : ""}`}
                onClick={() => navFinding(e.id)}
              >
                {e.title}
              </button>
            ))}
          </div>
        ))}
      </div>
      <div className="doc-content">{content}</div>
    </div>
  );
}
