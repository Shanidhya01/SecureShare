/**
 * VirusTotal provider for Phase 7 IOC lookups - reuses VIRUSTOTAL_API_KEY (same env var as
 * Phase 4's backend/services/virusTotalLookup.js) and extends coverage to domains/URLs, on top
 * of the hash lookups Phase 4 already does. Gracefully skips if the key is unset.
 */
import { httpsGetJson, SKIPPED } from "./providerUtils.js";

export const name = "VirusTotal";
export const supportedTypes = ["sha256", "sha1", "md5", "domain", "url"];

function toVerdict(stats) {
  const malicious = stats?.malicious || 0;
  const suspicious = stats?.suspicious || 0;
  const total = Object.values(stats || {}).reduce((s, n) => s + (typeof n === "number" ? n : 0), 0) || 1;
  if (malicious > 0) return { status: "malicious", confidence: Math.min(100, 60 + malicious * 5), severity: "Critical" };
  if (suspicious > 0) return { status: "suspicious", confidence: 40 + suspicious * 5, severity: "Medium" };
  return { status: "clean", confidence: Math.round((malicious / total) * 100), severity: "Low" };
}

export async function lookup(type, value) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return SKIPPED;

  try {
    let path;
    if (["sha256", "sha1", "md5"].includes(type)) path = `/api/v3/files/${value}`;
    else if (type === "domain") path = `/api/v3/domains/${encodeURIComponent(value)}`;
    else if (type === "url") {
      const urlId = Buffer.from(value).toString("base64").replace(/=+$/, "");
      path = `/api/v3/urls/${urlId}`;
    } else return SKIPPED;

    const body = await httpsGetJson("www.virustotal.com", path, { "x-apikey": apiKey });
    if (body?.notFoundStatus) return { status: "unknown", confidence: 0, severity: "Low", threatNames: [] };

    const stats = body?.data?.attributes?.last_analysis_stats;
    const results = body?.data?.attributes?.last_analysis_results || {};
    const threatNames = Object.values(results)
      .filter((r) => r?.category === "malicious" && r?.result)
      .map((r) => r.result)
      .slice(0, 10);

    return { ...toVerdict(stats), threatNames };
  } catch (err) {
    return { status: "error", confidence: 0, severity: "Low", threatNames: [], error: err.message };
  }
}
