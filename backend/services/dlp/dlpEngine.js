/**
 * Orchestrates a full Phase 5 DLP scan of a plaintext file buffer: skips binary/unsupported
 * files gracefully, runs every registered detector (backend/services/dlp/detectors) against the
 * extracted text, aggregates findings (masked - raw secret values are never returned or
 * persisted), and applies the configurable policy (dlpPolicyConfig.js) to reach a decision.
 *
 * Mirrors backend/services/threatScanService.js's shape: a pure-ish orchestrator returning a
 * plain object matching the DLPScan schema's scan-result fields; callers (dlp.controller.js,
 * file.controller.js's legacy v1 upload) persist the actual DLPScan document.
 */
import { DETECTORS } from "./detectors/index.js";
import { extractScannableText } from "./textFileSupport.js";
import { resolveDecision } from "./dlpPolicyConfig.js";
import { maskValue } from "./maskUtils.js";

const SEVERITY_RANK = { Low: 1, Medium: 2, High: 3, Critical: 4 };

function overallSeverity(findings) {
  if (findings.length === 0) return "None";
  return findings.reduce(
    (worst, f) => (SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst] ? f.severity : worst),
    "Low"
  );
}

/**
 * @param {Buffer} buffer - plaintext file content, never persisted
 * @param {{ originalFilename: string, claimedMimeType?: string, detectedMimeType?: string }} meta
 */
export function runDLPScan(buffer, meta) {
  const { originalFilename } = meta;
  const extraction = extractScannableText(buffer, meta);

  if (!extraction.supported) {
    return {
      originalFilename,
      fileSizeBytes: buffer.length,
      supported: false,
      skipReason: extraction.reason,
      findings: [],
      matchedPatterns: [],
      severity: "None",
      decision: "allow",
      policy: resolveDecision([]).policySnapshot,
      scanStatus: "completed"
    };
  }

  const findings = [];
  for (const detector of DETECTORS) {
    let matches;
    try {
      matches = detector.detect(extraction.text) || [];
    } catch (err) {
      // A single misbehaving detector must never take down the whole scan.
      console.error(`DLP detector "${detector.id}" failed:`, err);
      matches = [];
    }
    if (matches.length === 0) continue;

    findings.push({
      detectorId: detector.id,
      label: detector.label,
      category: detector.category,
      severity: detector.severity,
      count: matches.length,
      samples: [...new Set(matches)].slice(0, 5).map(maskValue)
    });
  }

  const { decision, policySnapshot } = resolveDecision(findings);

  return {
    originalFilename,
    fileSizeBytes: buffer.length,
    supported: true,
    truncated: !!extraction.truncated,
    findings,
    matchedPatterns: findings.map((f) => f.detectorId),
    severity: overallSeverity(findings),
    decision,
    policy: policySnapshot,
    scanStatus: "completed"
  };
}
