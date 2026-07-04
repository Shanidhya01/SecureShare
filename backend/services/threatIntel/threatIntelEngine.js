/**
 * Phase 7 orchestrator - mirrors dlpEngine.js's runDLPScan shape: a pure-ish function returning a
 * plain object matching ThreatIntelScan's fields, persisted by the caller (threatIntelIntegration.js
 * for the automatic upload-pipeline path, threatIntel.controller.js for the on-demand text-scan path).
 *
 * Two input modes:
 *  - hashes only (the automatic post-upload path - by then the server no longer holds plaintext,
 *    consistent with zero-knowledge encryption, so only hashes already computed by ThreatScan are
 *    available)
 *  - hashes + explicit plaintext (the on-demand POST /api/threat-intel/scan-text path, where a
 *    caller deliberately submits text to check, the same "explicit pre-encryption step" pattern
 *    Phase 4/5 use for file scanning)
 */
import { lookupMany } from "./iocLookupService.js";
import { extractIndicators } from "./extractors.js";
import { runYaraRules } from "./yaraEngine.js";
import { mapToMitre } from "./mitreMapping.js";

const SEVERITY_RANK = { None: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

function overallSeverity(iocMatches, yaraMatches) {
  let worst = "None";
  for (const m of [...iocMatches, ...yaraMatches]) {
    if (SEVERITY_RANK[m.severity] > SEVERITY_RANK[worst]) worst = m.severity;
  }
  return worst;
}

/**
 * @param {{ hashes?: {sha256?: string, sha1?: string, md5?: string}, text?: string, filename?: string }} input
 */
export async function runThreatIntelScan({ hashes = {}, text = null, filename = null } = {}) {
  const indicators = [];
  if (hashes.sha256) indicators.push({ type: "sha256", value: hashes.sha256 });
  if (hashes.sha1) indicators.push({ type: "sha1", value: hashes.sha1 });
  if (hashes.md5) indicators.push({ type: "md5", value: hashes.md5 });

  let extraction = { urls: [], domains: [], emails: [], ips: [] };
  if (text) {
    extraction = extractIndicators(text);
    extraction.urls.forEach((v) => indicators.push({ type: "url", value: v }));
    extraction.domains.forEach((v) => indicators.push({ type: "domain", value: v }));
    extraction.emails.forEach((v) => indicators.push({ type: "email", value: v }));
    extraction.ips.forEach((v) => indicators.push({ type: "ip", value: v }));
  }
  if (filename) indicators.push({ type: "filename", value: filename });

  let iocMatches = [];
  const providerErrors = new Set();
  try {
    const matches = await lookupMany(indicators);
    iocMatches = matches.map((m) => ({
      type: m.type,
      value: m.value,
      confidence: m.confidence,
      severity: m.severity,
      source: m.sources.join(", ") || "local",
      description: m.descriptions.join("; ") || undefined
    }));
    matches.forEach((m) => m.providerErrors.forEach((p) => providerErrors.add(p)));
  } catch (err) {
    console.error("Threat intel IOC lookup failed:", err);
  }

  let yaraResult = { skipped: true, matches: [] };
  try {
    yaraResult = await runYaraRules(text);
  } catch (err) {
    console.error("Threat intel YARA run failed:", err);
  }

  const mitreHints = [
    ...iocMatches.flatMap((m) => [m.type, m.description]),
    ...yaraResult.matches.flatMap((m) => [m.ruleName, ...m.mitreTechniques])
  ];
  const mitreMapping = mapToMitre(mitreHints);

  const threatSources = [...new Set(iocMatches.map((m) => m.source).flatMap((s) => s.split(", ")))];
  const severity = overallSeverity(iocMatches, yaraResult.matches);

  const confidenceValues = iocMatches.map((m) => m.confidence);
  const threatConfidence = confidenceValues.length ? Math.round(Math.max(...confidenceValues)) : 0;
  const threatScore = Math.min(
    100,
    iocMatches.length * 20 + yaraResult.matches.length * 25 + (severity === "Critical" ? 20 : 0)
  );

  return {
    iocMatches,
    mitreMapping,
    yaraMatches: yaraResult.matches,
    threatSources,
    providerErrors: [...providerErrors],
    threatScore,
    threatConfidence,
    severity,
    scanStatus: "completed",
    enrichedAt: new Date()
  };
}
