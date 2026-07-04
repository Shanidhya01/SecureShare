/**
 * AlienVault OTX provider for Phase 7 - covers IP/domain/hash pulse lookups. Skips gracefully if
 * OTX_API_KEY isn't set.
 */
import { httpsGetJson, SKIPPED } from "./providerUtils.js";

export const name = "AlienVault OTX";
export const supportedTypes = ["ip", "domain", "sha256", "sha1", "md5"];

const SECTION_BY_TYPE = { ip: "IPv4", domain: "domain", sha256: "file", sha1: "file", md5: "file" };

export async function lookup(type, value) {
  const apiKey = process.env.OTX_API_KEY;
  if (!apiKey || !SECTION_BY_TYPE[type]) return SKIPPED;

  try {
    const indicatorType = ["sha256", "sha1", "md5"].includes(type) ? "file" : SECTION_BY_TYPE[type];
    const body = await httpsGetJson(
      "otx.alienvault.com",
      `/api/v1/indicators/${indicatorType}/${encodeURIComponent(value)}/general`,
      { "X-OTX-API-KEY": apiKey }
    );
    const pulseCount = body?.pulse_info?.count || 0;
    if (pulseCount === 0) return { status: "unknown", confidence: 0, severity: "Low", threatNames: [] };

    const tags = (body?.pulse_info?.pulses || []).flatMap((p) => p.tags || []).slice(0, 10);
    const confidence = Math.min(100, pulseCount * 15);
    const severity = pulseCount >= 5 ? "Critical" : pulseCount >= 2 ? "High" : "Medium";
    return { status: "malicious", confidence, severity, threatNames: tags };
  } catch (err) {
    return { status: "error", confidence: 0, severity: "Low", threatNames: [], error: err.message };
  }
}
