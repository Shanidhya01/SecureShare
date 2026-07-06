/**
 * Configurable DLP policy (Phase 5) - pure data + a pure resolver function, following the same
 * tunable-constant pattern as backend/services/riskEngine.js's RISK_CONFIG. Edit this object (or
 * pass a custom config into resolveDecision) to change enforcement without touching call sites.
 *
 * Four possible decisions per scan, applied to the whole scan (the most severe finding wins):
 *   - "allow"            no action needed, upload proceeds silently
 *   - "warn"              upload proceeds, but the uploader is shown a non-blocking warning
 *   - "require_approval"  upload is held until the uploader explicitly acknowledges the finding
 *                          (POST /api/dlp/scans/:id/acknowledge), then proceeds
 *   - "block"              upload is refused outright; the file is never encrypted/stored
 */

/** Default action per overall finding severity, used when a detector has no explicit override. */
export const SEVERITY_ACTION = {
  Low: "allow",
  Medium: "warn",
  High: "require_approval",
  Critical: "block"
};

/**
 * Per-detector overrides: some detector categories warrant a different action than their raw
 * severity would suggest. Credentials/keys are always blocked outright regardless of a single
 * match's severity; broad PII heuristics (phone/passport) are downgraded to "warn" since they
 * carry a higher false-positive rate and blocking on them would be too disruptive.
 */
export const DETECTOR_ACTION_OVERRIDES = {
  aws_access_key: "block",
  aws_secret_key: "block",
  github_token: "block",
  gitlab_token: "block",
  google_api_key: "block",
  openai_api_key: "block",
  pem_private_key: "block",
  password_assignment: "block",
  env_secret: "block",
  credit_card: "block",
  jwt_token: "require_approval",
  aadhaar: "require_approval",
  pan: "require_approval",
  passport: "warn",
  phone: "warn",
  email: "allow",
  certificate: "allow",
  iban: "require_approval",
  swift_bic: "warn"
};

const ACTION_PRIORITY = { block: 3, require_approval: 2, warn: 1, allow: 0 };

/** @param {string[]} matchedDetectorIds */
function actionForDetector(detectorId, severity) {
  return DETECTOR_ACTION_OVERRIDES[detectorId] || SEVERITY_ACTION[severity] || "allow";
}

/**
 * @param {Array<{detectorId: string, severity: string, decisionHint?: string}>} findings - a
 *   finding may carry a `decisionHint` (set by dlpEngine.js when a detector's confidence-based
 *   analysis - see confidenceEngine.js - already produced a decision for this specific match, e.g.
 *   a LOW-confidence credit-card candidate that turned out to be a Ride ID). When present, it
 *   takes priority over the blanket per-detector/severity policy below, since it reflects an
 *   actual per-instance risk assessment rather than "this detector type is always dangerous".
 * @param {object} [config] - override policy config, defaults to the module-level exports above
 * @returns {{decision: string, policySnapshot: object}}
 */
export function resolveDecision(findings, config = {}) {
  const severityAction = { ...SEVERITY_ACTION, ...(config.severityAction || {}) };
  const overrides = { ...DETECTOR_ACTION_OVERRIDES, ...(config.detectorOverrides || {}) };

  let decision = "allow";
  for (const finding of findings) {
    const action = finding.decisionHint || overrides[finding.detectorId] || severityAction[finding.severity] || "allow";
    if (ACTION_PRIORITY[action] > ACTION_PRIORITY[decision]) decision = action;
  }

  return {
    decision,
    policySnapshot: { severityAction, detectorOverrides: overrides }
  };
}
