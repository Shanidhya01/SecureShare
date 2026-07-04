/**
 * AbuseIPDB provider for Phase 7 IP reputation lookups. Skips gracefully if ABUSEIPDB_API_KEY
 * isn't set.
 */
import { httpsGetJson, SKIPPED } from "./providerUtils.js";

export const name = "AbuseIPDB";
export const supportedTypes = ["ip"];

export async function lookup(type, value) {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (type !== "ip" || !apiKey) return SKIPPED;

  try {
    const body = await httpsGetJson(
      "api.abuseipdb.com",
      `/api/v2/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=90`,
      { Key: apiKey, Accept: "application/json" }
    );
    const score = body?.data?.abuseConfidenceScore ?? 0;
    let status = "clean";
    let severity = "Low";
    if (score >= 75) { status = "malicious"; severity = "Critical"; }
    else if (score >= 25) { status = "suspicious"; severity = "Medium"; }

    return { status, confidence: score, severity, threatNames: body?.data?.usageType ? [body.data.usageType] : [] };
  } catch (err) {
    return { status: "error", confidence: 0, severity: "Low", threatNames: [], error: err.message };
  }
}
