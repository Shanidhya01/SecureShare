/**
 * Phase 10 (Compliance & Governance): pure risk-score aggregation, split out from
 * complianceEngine.js so it's directly unit-testable like controlEvaluators.js/ruleMatcher.js.
 * Converts a set of ComplianceAssessment-shaped results (plus each control's static `severity`)
 * into a single 0-100 risk score - the inverse of "how compliant we are," weighted so that a
 * failed CRITICAL control counts far more than a failed LOW one.
 */

const SEVERITY_WEIGHT = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3, INFO: 1 };
const STATUS_MULTIPLIER = { FAIL: 1, PARTIAL: 0.5, PASS: 0, NOT_APPLICABLE: 0 };

/**
 * @param {Array<{status:string, severity?:string}>} assessments - assessment + control.severity merged per row
 * @returns {number} 0-100 risk score (0 = no risk, 100 = maximum observed risk)
 */
export function computeRiskScore(assessments) {
  if (!assessments || assessments.length === 0) return 0;

  const raw = assessments.reduce((sum, a) => {
    const weight = SEVERITY_WEIGHT[a.severity] ?? SEVERITY_WEIGHT.MEDIUM;
    const multiplier = STATUS_MULTIPLIER[a.status] ?? 0;
    return sum + weight * multiplier;
  }, 0);

  return Math.max(0, Math.min(100, Math.round(raw)));
}

/** Buckets assessments into Low/Medium/High/Critical risk tiers for a risk-distribution chart. */
export function riskDistribution(assessments) {
  const buckets = { Low: 0, Medium: 0, High: 0, Critical: 0 };
  for (const a of assessments || []) {
    if (a.status === "PASS" || a.status === "NOT_APPLICABLE") continue;
    const severity = a.severity || "MEDIUM";
    if (severity === "CRITICAL") buckets.Critical++;
    else if (severity === "HIGH") buckets.High++;
    else if (severity === "LOW") buckets.Low++;
    else buckets.Medium++;
  }
  return buckets;
}

/** Groups a list of `{ score, evaluatedAt }` assessment rows into a day-by-day average-score trend. */
export function buildComplianceTrend(assessments) {
  const byDay = new Map();
  for (const a of assessments || []) {
    const day = new Date(a.evaluatedAt).toISOString().slice(0, 10);
    if (!byDay.has(day)) byDay.set(day, { day, total: 0, count: 0 });
    const bucket = byDay.get(day);
    bucket.total += a.score;
    bucket.count += 1;
  }
  return Array.from(byDay.values())
    .map((b) => ({ day: b.day, averageScore: Math.round(b.total / b.count) }))
    .sort((a, b) => (a.day < b.day ? -1 : 1));
}
