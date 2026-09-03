import { useEffect, useState } from "react";
import { GetDocContent } from "../../wailsjs/go/main/App";
import { Locale, t } from "../i18n";
import { renderMarkdown } from "../utils/markdown";

type Props = { onBack: () => void; locale: Locale };

export function HelpView({ onBack, locale }: Props) {
  const [body, setBody] = useState<string | null>(null);

  useEffect(() => {
    setBody(null);
    const path = locale === "de" ? "guide-de" : "guide";
    void GetDocContent(path).then(md => setBody(md || null)).catch(() => setBody(null));
  }, [locale]);

  return (
    <div className="doc-layout" style={{flex:1}}>
      <div className="doc-toc">
        <div className="doc-toc-sticky">
          <button className="doc-toc-back" onClick={onBack}>{t(locale, "docsBack")}</button>
        </div>
        <div className="doc-toc-title" style={{padding:"12px 16px 4px"}}>{t(locale, "tbHelp")}</div>
      </div>
      <div className="doc-content">
        <div className="doc-article">
          {body === null
            ? <p className="muted">{t(locale, "docsLoading")}</p>
            : body
            ? renderMarkdown(body)
            : <p className="muted">{t(locale, "docsNotFound")}</p>
          }
        </div>
      </div>
    </div>
  );
}
