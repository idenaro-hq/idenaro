export type NIS2Article = {
  id: string;
  ref: string;
  title: string;
  titleDe: string;
  tags: string[];
};

export const NIS2_ARTICLES: NIS2Article[] = [
  { id: "21-2-a",        ref: "Art. 21 (2)(a) NIS2",         title: "Risk Analysis & Security Policies",               titleDe: "Risikoanalyse & Sicherheitsrichtlinien",            tags: ["admin-exposure", "zero-trust", "cors", "chain"] },
  { id: "21-2-d",        ref: "Art. 21 (2)(d) NIS2",         title: "Supply Chain Security",                           titleDe: "Lieferkettensicherheit",                            tags: ["scim", "chain"] },
  { id: "21-2-e",        ref: "Art. 21 (2)(e) NIS2",         title: "Secure Acquisition, Development & Maintenance",   titleDe: "Sichere Beschaffung, Entwicklung & Wartung",        tags: ["headers", "admin-exposure", "endpoints", "cookies", "cors", "csp", "redirects", "enumeration", "chain"] },
  { id: "21-2-g",        ref: "Art. 21 (2)(g) NIS2",         title: "Basic Cyber Hygiene & Training",                  titleDe: "Grundlegende Cyber-Hygiene & Schulung",             tags: ["headers", "endpoints", "csp", "lifecycle"] },
  { id: "21-2-h",        ref: "Art. 21 (2)(h) NIS2",         title: "Cryptography & Encryption",                       titleDe: "Kryptografie & Verschlüsselung",                    tags: ["tls", "cookies", "tokens"] },
  { id: "21-2-i",        ref: "Art. 21 (2)(i) NIS2",         title: "Access Control & Asset Management",               titleDe: "Zugangskontrolle & Asset-Management",               tags: ["iam", "mfa", "oidc", "saml", "admin-exposure", "zero-trust", "endpoints", "redirects", "enumeration", "scim", "tokens", "lifecycle"] },
  { id: "21-2-j",        ref: "Art. 21 (2)(j) NIS2",         title: "Multi-Factor Authentication & Secured Communications", titleDe: "Multi-Faktor-Authentifizierung & Sichere Kommunikation", tags: ["iam", "mfa", "oidc", "saml", "tls", "cookies", "zero-trust", "tokens"] },
  { id: "21-2-combined", ref: "Art. 21 (2) - Chain Findings", title: "Combined Risk of Multiple Weaknesses",            titleDe: "Kombiniertes Risiko mehrerer Schwachstellen",       tags: ["chain"] },
];
