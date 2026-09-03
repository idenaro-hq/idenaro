import { useEffect, useState } from "react";
import { GetDocContent } from "../../wailsjs/go/main/App";
import { Locale, t } from "../i18n";
import { NIS2_ARTICLES } from "../data/nis2Data";
import { renderMarkdown } from "../utils/markdown";

type Props = { onBack: () => void; locale: Locale };

export function NIS2View({ onBack, locale }: Props) {
  const [active, setActive]   = useState(NIS2_ARTICLES[0].id);
  const [body, setBody]       = useState<string>("");
  const [loading, setLoading] = useState(false);
  const article = NIS2_ARTICLES.find(a => a.id === active) ?? NIS2_ARTICLES[0];

  useEffect(() => {
    setLoading(true);
    setBody("");
    const path = locale === "de" ? `nis2/${active}-de` : `nis2/${active}`;
    void GetDocContent(path)
      .then(md => {
        if (md) { setBody(md); setLoading(false); return; }
        void GetDocContent(`nis2/${active}`)
          .then(mdEn => { setBody(mdEn); setLoading(false); })
          .catch(() => setLoading(false));
      })
      .catch(() => setLoading(false));
  }, [active, locale]);

  return (
    <div className="nis2-layout" style={{flex:1}}>
      <div className="nis2-toc">
        <div className="doc-toc-sticky">
          <button className="doc-toc-back" onClick={onBack}>{t(locale, "docsBack")}</button>
        </div>
        <div className="nis2-toc-title">{t(locale, "nis2Articles")}</div>
        {NIS2_ARTICLES.map(a => (
          <button key={a.id} className={`nis2-toc-item ${active === a.id ? "active" : ""}`} onClick={() => setActive(a.id)}>
            {locale === "de" ? a.titleDe : a.title}
          </button>
        ))}
      </div>
      <div className="nis2-content">
        <div className="nis2-article" key={article.id}>
          <div className="nis2-article-ref">{article.ref}</div>
          <div className="nis2-article-title">{locale === "de" ? article.titleDe : article.title}</div>
          <div className="nis2-divider"/>
          {loading
            ? <p className="muted">{t(locale, "docsLoading")}</p>
            : body
            ? renderMarkdown(body)
            : <p className="muted">{t(locale, "docsNotFound")}</p>
          }
          <div className="nis2-divider"/>
          <div className="fsect-label" style={{marginBottom:8}}>{t(locale, "nis2TagsLabel")}</div>
          <div>{article.tags.map(tag => <span key={tag} className="nis2-mapping-tag">{tag}</span>)}</div>
        </div>
      </div>
    </div>
  );
}
