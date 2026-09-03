import React from "react";

export function renderInline(text: string): React.ReactNode {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*)/);
  return parts.map((p, i) => {
    if (p.startsWith("**") && p.endsWith("**")) return <strong key={i}>{p.slice(2, -2)}</strong>;
    if (p.startsWith("*")  && p.endsWith("*"))  return <em key={i}>{p.slice(1, -1)}</em>;
    if (p.startsWith("`")  && p.endsWith("`"))  return <code key={i}>{p.slice(1, -1)}</code>;
    return p;
  });
}

export function renderMarkdown(md: string): React.ReactNode {
  const lines = md.split("\n");
  const nodes: React.ReactNode[] = [];
  let i = 0;
  let key = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (line.startsWith("### ")) { nodes.push(<h3 key={key++}>{renderInline(line.slice(4))}</h3>); i++; continue; }
    if (line.startsWith("## "))  { nodes.push(<h2 key={key++}>{renderInline(line.slice(3))}</h2>); i++; continue; }
    if (line.startsWith("# "))   { nodes.push(<h1 key={key++}>{renderInline(line.slice(2))}</h1>); i++; continue; }
    if (line.startsWith("- ")) {
      const items: string[] = [];
      while (i < lines.length && lines[i].startsWith("- ")) { items.push(lines[i].slice(2)); i++; }
      nodes.push(<ul key={key++}>{items.map((item, j) => <li key={j}>{renderInline(item)}</li>)}</ul>);
      continue;
    }
    if (line.trim() === "" || line.trim() === "---") { i++; continue; }
    nodes.push(<p key={key++}>{renderInline(line)}</p>);
    i++;
  }
  return <>{nodes}</>;
}

// Parses a grouped module markdown file into entries keyed by finding id.
// Each section is separated by "---" and starts with "## id | title | severity".
export function parseGroupedMd(src: string): Record<string, string> {
  const result: Record<string, string> = {};
  const sections = src.split(/\n---\n/);
  for (const section of sections) {
    const trimmed = section.trim();
    if (!trimmed) continue;
    const firstNl = trimmed.indexOf("\n");
    if (firstNl < 0) continue;
    const header = trimmed.slice(0, firstNl).trim();
    const body   = trimmed.slice(firstNl + 1).trim();
    const parts  = header.replace(/^##\s*/, "").split("|");
    if (parts.length >= 1) {
      result[parts[0].trim()] = body;
    }
  }
  return result;
}
