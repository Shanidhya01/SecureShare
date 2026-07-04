/**
 * Phase 10 (Compliance & Governance): CompliancePolicy read/versioning helpers plus pure
 * violation-checking logic. `getCurrentPolicyValues()` is the one DB-touching function here (it
 * resolves the latest enabled version per policy name); `evaluatePolicyViolation()` below it is
 * pure and unit-testable, mirroring services/soar/ruleMatcher.js's evaluateCondition() split.
 */
import CompliancePolicy from "../../models/CompliancePolicy.js";

const POLICY_DEFAULTS = {
  FILE_RETENTION_DAYS: 365,
  MAX_UPLOAD_SIZE_MB: 100,
  BLOCKED_FILE_TYPES: [],
  RESTRICTED_COUNTRIES: [],
  DLP_ENFORCEMENT: true
};

const POLICY_NAMES = Object.keys(POLICY_DEFAULTS);

/** Resolves the current (highest-versioned, enabled) value for every governance policy name. */
export async function getCurrentPolicyValues() {
  const docs = await CompliancePolicy.find({ enabled: true }).sort({ version: -1 }).lean();
  const values = { ...POLICY_DEFAULTS };
  const seen = new Set();
  for (const doc of docs) {
    if (seen.has(doc.name)) continue; // already have the highest version for this name
    seen.add(doc.name);
    values[doc.name] = doc.value;
  }
  return values;
}

export async function listCurrentPolicies() {
  const values = await getCurrentPolicyValues();
  const results = await Promise.all(
    POLICY_NAMES.map(async (name) => {
      const latest = await CompliancePolicy.findOne({ name }).sort({ version: -1 }).lean();
      return {
        name,
        value: values[name],
        version: latest?.version || 0,
        enabled: latest ? latest.enabled : true,
        updatedAt: latest?.updatedAt || null
      };
    })
  );
  return results;
}

/**
 * Pure shape/range validation for a policy value before it's persisted - the "Policy Validation"
 * requirement. Returns an error string, or null if the value is acceptable.
 */
export function validatePolicyValue(name, value) {
  switch (name) {
    case "FILE_RETENTION_DAYS":
    case "MAX_UPLOAD_SIZE_MB":
      return typeof value === "number" && value > 0 ? null : `${name} must be a positive number`;
    case "BLOCKED_FILE_TYPES":
    case "RESTRICTED_COUNTRIES":
      return Array.isArray(value) && value.every((v) => typeof v === "string")
        ? null
        : `${name} must be an array of strings`;
    case "DLP_ENFORCEMENT":
      return typeof value === "boolean" ? null : `${name} must be a boolean`;
    default:
      return `Unknown policy name: ${name}`;
  }
}

/** Creates a new versioned CompliancePolicy document for `name`, incrementing from the latest version. */
export async function setPolicyValue({ name, value, enabled, updatedBy }) {
  if (!POLICY_NAMES.includes(name)) throw new Error(`Unknown policy name: ${name}`);
  const validationError = validatePolicyValue(name, value);
  if (validationError) throw new Error(validationError);

  const latest = await CompliancePolicy.findOne({ name }).sort({ version: -1 }).lean();
  return CompliancePolicy.create({
    name,
    value,
    version: (latest?.version || 0) + 1,
    enabled: enabled !== false,
    updatedBy: updatedBy || null
  });
}

/** Full version history for a policy name, most recent first - the "History" requirement. */
export async function getPolicyHistory(name) {
  return CompliancePolicy.find({ name }).sort({ version: -1 }).lean();
}

/**
 * Rollback: re-activates an older version's value as a brand-new version (never mutates or
 * deletes history), matching the "never mutate, always append" versioning convention above.
 */
export async function rollbackPolicy({ name, version, updatedBy }) {
  const target = await CompliancePolicy.findOne({ name, version }).lean();
  if (!target) throw new Error(`No version ${version} found for policy ${name}`);
  return setPolicyValue({ name, value: target.value, enabled: true, updatedBy });
}

/** Marks a specific policy version document as reviewed - the "Approval Status" requirement. */
export async function setPolicyApproval({ id, status, approvedBy }) {
  if (!["pending", "approved", "rejected"].includes(status)) throw new Error(`Invalid approval status: ${status}`);
  return CompliancePolicy.findByIdAndUpdate(
    id,
    { approvalStatus: status, approvedBy: approvedBy || null, approvedAt: new Date() },
    { new: true }
  );
}

/** Enable/disable a specific policy version document directly (by its own _id), without creating
 *  a new version - used for the "Enable/Disable" requirement at the individual-version level. */
export async function setPolicyVersionEnabled({ id, enabled }) {
  return CompliancePolicy.findByIdAndUpdate(id, { enabled: !!enabled }, { new: true });
}

/**
 * Pure check: given current policy values and a piece of observed state, returns a list of
 * violation descriptions (empty if compliant). `state` fields are optional - only the ones
 * relevant to a given policy need be present.
 */
export function evaluatePolicyViolations(policyValues, state = {}) {
  const violations = [];

  if (typeof state.uploadSizeMB === "number" && state.uploadSizeMB > (policyValues.MAX_UPLOAD_SIZE_MB ?? Infinity)) {
    violations.push(`Upload size ${state.uploadSizeMB}MB exceeds MAX_UPLOAD_SIZE_MB (${policyValues.MAX_UPLOAD_SIZE_MB}MB)`);
  }
  if (state.fileExtension && (policyValues.BLOCKED_FILE_TYPES || []).includes(state.fileExtension.toLowerCase())) {
    violations.push(`File type "${state.fileExtension}" is blocked by BLOCKED_FILE_TYPES policy`);
  }
  if (state.country && (policyValues.RESTRICTED_COUNTRIES || []).includes(state.country)) {
    violations.push(`Access from restricted country "${state.country}"`);
  }
  if (state.dlpDecision === "block" && !policyValues.DLP_ENFORCEMENT) {
    violations.push("DLP flagged a block-worthy finding but DLP_ENFORCEMENT policy is disabled");
  }

  return violations;
}

export { POLICY_NAMES, POLICY_DEFAULTS };
