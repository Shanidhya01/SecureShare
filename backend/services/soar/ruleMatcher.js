/**
 * Phase 8 (SOAR): pure, DB-free rule matching - mirrors
 * backend/services/siem/correlationEngine.js's evaluateRules() pattern so it's directly unit
 * testable (see backend/tests/soarEngine.test.js) without touching Mongo.
 *
 * eventTriggerFor() maps an already-logged SecurityEvent onto one of AutomationRule's `trigger`
 * enum values. SESSION_COMPROMISED still has no emitter anywhere in this codebase - accepted by
 * the schema/UI for forward compatibility but never fires today. MULTIPLE_FAILED_LOGINS, however,
 * went live in Phase 9 (IAM): backend/services/iam/loginFailureTracker.js now logs a
 * `login_failed` event carrying a rolling 15-minute failure count in `metadata.recentFailureCount`
 * on every bad password/MFA attempt, and the conditional mapping below fires once that count
 * reaches 3 - the same "map based on event metadata" pattern already used for MITRE_CRITICAL.
 * Phase 9.5 adds two more: IMPOSSIBLE_TRAVEL (unconditional - every `impossible_travel` event is
 * inherently critical) and CRITICAL_RISK_LOGIN (conditional on `step_up_auth`'s `riskLevel`
 * metadata, set by backend/services/iam/loginRiskEngine.js's four-tier scoring).
 */

// A curated subset of MITRE tactics considered "critical" for the MITRE_CRITICAL trigger -
// mirrors the severity judgment calls already made in backend/services/threatIntel/mitreMapping.js.
const CRITICAL_MITRE_TACTICS = ["Impact", "Credential Access", "Exfiltration", "Command and Control"];

export function eventTriggerFor(event) {
  switch (event.type) {
    case "threat_found":
      return "THREAT_FOUND";
    case "ioc_match":
    case "threat_intel_match":
      return "IOC_MATCH";
    case "dlp_blocked":
      return "DLP_BLOCK";
    case "signature_invalid":
      return "SIGNATURE_FAILED";
    case "yara_match":
      return "YARA_MATCH";
    case "new_device":
      return "NEW_DEVICE";
    case "login_failed":
      return (event.metadata?.recentFailureCount || 0) >= 3 ? "MULTIPLE_FAILED_LOGINS" : null;
    case "impossible_travel":
      return "IMPOSSIBLE_TRAVEL";
    case "step_up_auth":
      return event.metadata?.riskLevel === "Critical" ? "CRITICAL_RISK_LOGIN" : null;
    case "compliance_scan":
      return event.metadata?.scoreDropped ? "COMPLIANCE_SCORE_DROP" : null;
    case "control_failed":
      return event.metadata?.severity === "CRITICAL" ? "COMPLIANCE_SCORE_DROP" : null;
    case "public_exposure":
      return ["CRITICAL", "HIGH"].includes(event.metadata?.severity) ? "PUBLIC_EXPOSURE_CRITICAL" : null;
    case "certificate_expired":
      return "CERTIFICATE_EXPIRED";
    case "cloud_ioc_match":
      return "IOC_MATCH";
    case "security_score_updated":
      return event.metadata?.scoreDropped ? "CLOUD_SCORE_DROP" : null;
    case "dependency_vulnerability":
      return ["CRITICAL", "HIGH"].includes(event.metadata?.severity) ? "DEPENDENCY_VULNERABILITY_CRITICAL" : null;
    case "secret_found":
      return ["CRITICAL", "HIGH"].includes(event.metadata?.severity) ? "SECRET_FOUND_CRITICAL" : null;
    case "container_vulnerability":
      return ["CRITICAL", "HIGH"].includes(event.metadata?.severity) ? "CONTAINER_VULNERABILITY_CRITICAL" : null;
    case "pipeline_blocked":
      return "PIPELINE_BLOCKED";
    case "high_risk_repository":
      return "HIGH_RISK_REPOSITORY";
    case "mitre_mapping": {
      const techniques = event.metadata?.techniques || [];
      const isCritical = techniques.some((t) => CRITICAL_MITRE_TACTICS.includes(t.tactic));
      return isCritical ? "MITRE_CRITICAL" : null;
    }
    default:
      return null;
  }
}

function getPath(obj, path) {
  return path.split(".").reduce((acc, key) => (acc == null ? undefined : acc[key]), obj);
}

/** @param {{field:string, operator:string, value:*}} condition */
export function evaluateCondition(condition, event) {
  const actual = getPath(event, condition.field);
  const expected = condition.value;

  switch (condition.operator) {
    case "eq":
      return actual === expected;
    case "neq":
      return actual !== expected;
    case "gt":
      return actual > expected;
    case "gte":
      return actual >= expected;
    case "lt":
      return actual < expected;
    case "lte":
      return actual <= expected;
    case "contains":
      return Array.isArray(actual) ? actual.includes(expected) : String(actual ?? "").includes(String(expected));
    case "in":
      return Array.isArray(expected) && expected.includes(actual);
    default:
      return false;
  }
}

/**
 * @param {object} event - a SecurityEvent-shaped object (plain object or lean doc)
 * @param {Array} rules - AutomationRule docs/plain objects
 * @returns {Array} matched rules, sorted by ascending priority (lower runs first)
 */
export function matchRules(event, rules) {
  const trigger = eventTriggerFor(event);
  if (!trigger) return [];

  return rules
    .filter((rule) => rule.enabled !== false && rule.trigger === trigger)
    .filter((rule) => (rule.conditions || []).every((c) => evaluateCondition(c, event)))
    .sort((a, b) => (a.priority ?? 100) - (b.priority ?? 100));
}
