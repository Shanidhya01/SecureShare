/**
 * Phase 8 (SOAR): pure, DB-free rule matching - mirrors
 * backend/services/siem/correlationEngine.js's evaluateRules() pattern so it's directly unit
 * testable (see backend/tests/soarEngine.test.js) without touching Mongo.
 *
 * eventTriggerFor() maps an already-logged SecurityEvent onto one of AutomationRule's `trigger`
 * enum values. Two triggers (SESSION_COMPROMISED, MULTIPLE_FAILED_LOGINS) have no emitter
 * anywhere in this codebase yet - no phase currently logs a failed-login or session-compromise
 * event - so they're accepted by the schema/UI for forward compatibility but never fire today.
 * This is documented, not a bug: adding failed-login logging would mean touching Phase 1/3 auth
 * flow, which is out of scope for a purely additive orchestration layer.
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
