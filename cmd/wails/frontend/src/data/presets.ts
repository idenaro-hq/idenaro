export const PRESETS: Record<string, string[]> = {
  "Full scan": [],
  "OIDC / OAuth2": ["oidc", "cors", "redirects", "tokens"],
  "Headers & Cookies": ["headers", "csp", "cookies", "cors"],
  "NIS2 Compliance": ["headers", "tls", "cookies", "tokens", "oidc", "saml", "mfa", "scim"],
  "Quick check": ["headers", "endpoints", "mfa", "tls", "cookies"],
};

export const FREE_MODULE_SET = new Set(["oidc", "saml", "headers", "endpoints"]);

export const PRO_MODULES = [
  "oidc-pro", "saml-pro", "tls", "cookies", "cors", "csp",
  "redirects", "tokens", "mfa", "lifecycle", "scim", "products", "enumeration",
];

export const SEV_ORDER: Record<string, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, chain: -1,
};

export function isProPreset(label: string): boolean {
  const preset = PRESETS[label];
  if (!preset || preset.length === 0) return false;
  return preset.some(m => !FREE_MODULE_SET.has(m));
}
