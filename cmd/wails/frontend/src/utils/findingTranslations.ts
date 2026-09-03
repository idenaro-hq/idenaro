import { useEffect, useState } from "react";
import { GetDocContent } from "../../wailsjs/go/main/App";
import { DOC_ENTRIES, GROUP_FILE } from "../data/docs";
import { parseGroupedMd } from "./markdown";
import type { Locale } from "../i18n";

export type FindingTexts = { description: string; recommendation: string };

function splitDescRec(body: string): FindingTexts {
  const h3 = body.indexOf("\n### ");
  if (h3 < 0) return { description: body.trim(), recommendation: "" };

  const description = body.slice(0, h3).trim();
  const rest = body.slice(h3 + 1);
  const nl = rest.indexOf("\n");
  if (nl < 0) return { description, recommendation: "" };

  const recommendation = rest
    .slice(nl + 1)
    .split("\n")
    .map(l => l.trim())
    .filter(l => l.startsWith("- "))
    .map(l => l.slice(2).trim())
    .join("\n");

  return { description, recommendation };
}

export function useFindingTranslations(locale: Locale): Map<string, FindingTexts> {
  const [translations, setTranslations] = useState<Map<string, FindingTexts>>(new Map());

  useEffect(() => {
    if (locale !== "de") {
      setTranslations(new Map());
      return;
    }

    const fileKeys = Array.from(new Set(
      DOC_ENTRIES.map(e => GROUP_FILE[e.group] ?? e.group.toLowerCase().replace(/[^a-z0-9]/g, ""))
    ));

    void Promise.all(
      fileKeys.map(fk =>
        GetDocContent(`modules/${fk}-de`)
          .then(md => md ? parseGroupedMd(md) : ({} as Record<string, string>))
          .catch(() => ({} as Record<string, string>))
      )
    ).then(results => {
      const map = new Map<string, FindingTexts>();
      for (const sections of results) {
        for (const [id, body] of Object.entries(sections)) {
          if (!id.endsWith("-overview")) {
            map.set(id, splitDescRec(body));
          }
        }
      }
      setTranslations(map);
    });
  }, [locale]);

  return translations;
}
