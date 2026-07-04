/**
 * Phase 7: dependency-free extraction of candidate IOC values (URLs, domains, emails, IPv4s) from
 * plaintext - used only by the on-demand POST /api/threat-intel/scan-text path (where a caller
 * explicitly submits text, mirroring how DLP/malware scans are explicit pre-encryption steps).
 * Never invoked against DLP's masked samples - those are intentionally not raw values.
 */
const URL_RE = /\bhttps?:\/\/[^\s"'<>)]+/gi;
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const EMAIL_RE = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
const DOMAIN_RE = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;

function unique(arr) {
  return [...new Set(arr)];
}

/**
 * @param {string} text
 * @returns {{ urls: string[], domains: string[], emails: string[], ips: string[] }}
 */
export function extractIndicators(text) {
  if (!text || typeof text !== "string") return { urls: [], domains: [], emails: [], ips: [] };

  const urls = unique(text.match(URL_RE) || []).slice(0, 50);
  const ips = unique(text.match(IPV4_RE) || []).slice(0, 50);
  const emails = unique(text.match(EMAIL_RE) || []).slice(0, 50);

  const domainsFromUrls = urls.map((u) => {
    try {
      return new URL(u).hostname.toLowerCase();
    } catch {
      return null;
    }
  }).filter(Boolean);

  const rawDomains = (text.match(DOMAIN_RE) || []).map((d) => d.toLowerCase());
  const domains = unique([...domainsFromUrls, ...rawDomains])
    .filter((d) => !ips.includes(d))
    .slice(0, 50);

  return { urls, domains, emails, ips };
}
