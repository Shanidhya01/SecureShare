/**
 * Phase 7 IOC lookup engine: checks the local IOC collection first (fast, offline, always
 * available) then fans out to applicable external providers (services/threatIntel/providers/),
 * merging every result into one normalized verdict. Mirrors dlpEngine.js's defensive iteration
 * over detectors - a single provider throwing/erroring never breaks the lookup or the caller.
 */
import IOC from "../../models/IOC.js";
import { PROVIDERS } from "./providers/index.js";

const SEVERITY_RANK = { Low: 1, Medium: 2, High: 3, Critical: 4 };

function worseSeverity(a, b) {
  return (SEVERITY_RANK[b] || 0) > (SEVERITY_RANK[a] || 0) ? b : a;
}

/**
 * @param {"ip"|"domain"|"url"|"sha256"|"sha1"|"md5"|"email"|"filename"|"cert_fingerprint"} type
 * @param {string} value
 * @returns {Promise<{ matched: boolean, confidence: number, severity: string, sources: string[], tags: string[], descriptions: string[], providerErrors: string[] }>}
 */
export async function lookupIOC(type, value) {
  const result = {
    matched: false,
    confidence: 0,
    severity: "Low",
    sources: [],
    tags: [],
    descriptions: [],
    providerErrors: []
  };

  // Local IOC database - always consulted, never requires network access.
  const localHit = await IOC.findOne({ type, value, status: "active" });
  if (localHit) {
    result.matched = true;
    result.confidence = Math.max(result.confidence, localHit.confidence);
    result.severity = worseSeverity(result.severity, localHit.severity);
    result.sources.push(localHit.source || "local");
    result.tags.push(...(localHit.tags || []));
    if (localHit.description) result.descriptions.push(localHit.description);
  }

  const applicableProviders = PROVIDERS.filter((p) => p.supportedTypes.includes(type));
  const settled = await Promise.allSettled(applicableProviders.map((p) => p.lookup(type, value)));

  settled.forEach((outcome, i) => {
    const provider = applicableProviders[i];
    if (outcome.status !== "fulfilled") {
      result.providerErrors.push(provider.name);
      return;
    }
    const verdict = outcome.value;
    if (!verdict || verdict.status === "skipped") return;
    if (verdict.status === "error") {
      result.providerErrors.push(provider.name);
      return;
    }
    if (verdict.status === "malicious" || verdict.status === "suspicious") {
      result.matched = true;
      result.confidence = Math.max(result.confidence, verdict.confidence || 0);
      result.severity = worseSeverity(result.severity, verdict.severity || "Low");
      result.sources.push(provider.name);
      result.tags.push(...(verdict.threatNames || []));
    }
  });

  result.tags = [...new Set(result.tags)];
  result.sources = [...new Set(result.sources)];
  return result;
}

/**
 * Batch helper - looks up many indicators, returns only matches, capped so a large extraction
 * result can't trigger an unbounded number of outbound provider calls.
 * @param {{type: string, value: string}[]} indicators
 */
export async function lookupMany(indicators, cap = 20) {
  const capped = indicators.slice(0, cap);
  const results = [];
  for (const { type, value } of capped) {
    const verdict = await lookupIOC(type, value);
    if (verdict.matched) {
      results.push({ type, value, ...verdict });
    }
  }
  return results;
}
