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

// Legacy (non-confidence-scoring) detectors only return a boolean match, so they don't have a
// per-instance confidence score. Their severity is used as a stand-in so every finding - whether
// confidence-scored or not - has the same shape for the risk report / UI (Part 6/7).
const CONFIDENCE_LEVEL_BY_SEVERITY = { Critical: "HIGH", High: "HIGH", Medium: "MEDIUM", Low: "LOW" };

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
    if (typeof detector.detectWithConfidence === "function") {
      let scored;
      try {
        scored = detector.detectWithConfidence(extraction.text) || [];
      } catch (err) {
        // A single misbehaving detector must never take down the whole scan.
        console.error(`DLP detector "${detector.id}" failed:`, err);
        scored = [];
      }
      if (scored.length === 0) continue;

      // The most-confident candidate drives the finding-level confidence/decision - it's the
      // instance most likely to be a genuine match, so it should decide whether this finding
      // escalates the overall scan decision (see resolveDecision's decisionHint handling).
      const worst = scored.reduce((max, c) => (c.confidenceScore > max.confidenceScore ? c : max), scored[0]);

      findings.push({
        detectorId: detector.id,
        label: detector.label,
        category: detector.category,
        severity: detector.severity,
        count: scored.length,
        samples: [...new Set(scored.map((c) => c.value))].slice(0, 5).map(maskValue),
        confidence: worst.confidenceScore,
        confidenceLevel: worst.confidenceLevel,
        reasons: worst.reasons,
        context: worst.context,
        decisionHint: worst.decision
      });
      continue;
    }

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
      samples: [...new Set(matches)].slice(0, 5).map(maskValue),
      confidence: 100,
      confidenceLevel: CONFIDENCE_LEVEL_BY_SEVERITY[detector.severity] || "MEDIUM",
      reasons: ["Regex pattern matched"],
      context: null
    });
  }

  const { decision, policySnapshot } = resolveDecision(findings);
  const riskReport = findings.map((f) => ({
    pattern: f.label,
    detectorId: f.detectorId,
    confidence: f.confidence,
    confidenceLevel: f.confidenceLevel,
    reasons: f.reasons,
    matchedText: f.samples,
    context: f.context,
    decision: f.decisionHint || decision
  }));

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
    riskReport,
    scanStatus: "completed"
  };
}
