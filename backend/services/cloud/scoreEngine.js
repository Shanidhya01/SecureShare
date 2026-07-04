/**
 * Phase 11 (CSPM/ASM) - PART 6/PART 13: computes the 6 component scores plus a weighted overall
 * security posture score. The severity-weight/status-multiplier approach mirrors
 * services/compliance/riskScoring.js's computeRiskScore() (copied, not imported - the finding
 * shape differs) so "how much does an open CRITICAL finding hurt the score" stays consistent with
 * the rest of the platform. `complianceScore`/`identityScore` reuse already-computed data from the
 * existing Compliance/IAM subsystems rather than re-deriving it.
 */
import Asset from "../../models/Asset.js";
import CloudFinding from "../../models/CloudFinding.js";
import Certificate from "../../models/Certificate.js";
import SecurityScoreSnapshot from "../../models/SecurityScoreSnapshot.js";
import User from "../../models/User.js";
import Device from "../../models/Device.js";
import ComplianceAssessment from "../../models/ComplianceAssessment.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

const SEVERITY_WEIGHT = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3, INFO: 1 };
const CRITICALITY_PENALTY = { critical: 25, high: 15, medium: 8, low: 3 };

function clampScore(n) {
  return Math.max(0, Math.min(100, Math.round(n)));
}

/** 100 minus the weighted sum of open findings' severities, floored at 0. */
function scoreFromOpenFindings(findings) {
  if (findings.length === 0) return 100;
  const penalty = findings.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] ?? SEVERITY_WEIGHT.MEDIUM), 0);
  return clampScore(100 - penalty);
}

async function computeAssetScore() {
  const assets = await Asset.find({ status: "active" }).select("riskScore criticality").lean();
  if (assets.length === 0) return 100;
  const penalty = assets.reduce((sum, a) => sum + (a.riskScore || 0) * 0.01 * (CRITICALITY_PENALTY[a.criticality] ?? 8), 0);
  return clampScore(100 - penalty / Math.max(1, assets.length));
}

async function computeConfigScore() {
  const findings = await CloudFinding.find({ category: "CONFIGURATION", status: "open" }).select("severity").lean();
  return scoreFromOpenFindings(findings);
}

async function computeExposureScore() {
  const findings = await CloudFinding.find({ category: "EXPOSURE", status: "open" }).select("severity").lean();
  return scoreFromOpenFindings(findings);
}

async function computeCertScore() {
  const certs = await Certificate.find().select("status").lean();
  if (certs.length === 0) return 100;
  const penalty = certs.reduce((sum, c) => {
    if (c.status === "expired") return sum + 40;
    if (c.status === "expiring") return sum + 15;
    if (c.status === "unreachable") return sum + 10;
    return sum;
  }, 0);
  return clampScore(100 - penalty);
}

async function computeIdentityScore() {
  const [totalUsers, mfaUsers, totalDevices, trustedDevices] = await Promise.all([
    User.countDocuments(),
    User.countDocuments({ "mfa.enabled": true }),
    Device.countDocuments(),
    Device.countDocuments({ trusted: true, revoked: false })
  ]);
  if (totalUsers === 0) return 100;
  const mfaRatio = mfaUsers / totalUsers;
  const deviceTrustRatio = totalDevices === 0 ? 1 : trustedDevices / totalDevices;
  return clampScore((mfaRatio * 0.6 + deviceTrustRatio * 0.4) * 100);
}

async function computeComplianceScore() {
  const latestAssessments = await ComplianceAssessment.find().sort({ evaluatedAt: -1 }).limit(1000).select("control score evaluatedAt").lean();
  if (latestAssessments.length === 0) return 100;

  const latestByControl = new Map();
  for (const a of latestAssessments) {
    const key = String(a.control);
    if (!latestByControl.has(key)) latestByControl.set(key, a);
  }
  const scores = [...latestByControl.values()].map((a) => a.score);
  return clampScore(scores.reduce((sum, s) => sum + s, 0) / scores.length);
}

// Weighted so configuration/exposure findings (directly actionable CSPM/ASM output) dominate the
// overall score, while identity/compliance (already scored by their own subsystems) contribute a
// meaningful but smaller share.
const WEIGHTS = { assetScore: 0.15, configScore: 0.2, exposureScore: 0.2, certScore: 0.15, identityScore: 0.15, complianceScore: 0.15 };

export function computeOverallScore(scores) {
  const overall = Object.entries(WEIGHTS).reduce((sum, [key, weight]) => sum + (scores[key] ?? 100) * weight, 0);
  return clampScore(overall);
}

const SCORE_DROP_THRESHOLD = 70;

export async function runScoreEngine({ owner } = {}) {
  const [assetScore, configScore, exposureScore, certScore, identityScore, complianceScore] = await Promise.all([
    computeAssetScore(),
    computeConfigScore(),
    computeExposureScore(),
    computeCertScore(),
    computeIdentityScore(),
    computeComplianceScore()
  ]);

  const scores = { assetScore, configScore, exposureScore, certScore, identityScore, complianceScore };
  const overallScore = computeOverallScore(scores);

  const snapshot = await SecurityScoreSnapshot.create({ ...scores, overallScore, scannedAt: new Date() });

  await logSecurityEvent({
    owner,
    type: "cloud_risk_updated",
    message: `Cloud risk posture recomputed (overall score ${overallScore})`,
    metadata: scores
  }).catch(() => {});

  await logSecurityEvent({
    owner,
    type: "security_score_updated",
    message: `Overall security score updated to ${overallScore}${overallScore < SCORE_DROP_THRESHOLD ? " (below threshold)" : ""}`,
    metadata: { overallScore, scoreDropped: overallScore < SCORE_DROP_THRESHOLD }
  }).catch(() => {});

  return { ...scores, overallScore, snapshotId: snapshot._id };
}

export async function getScoreHistory({ days = 90 } = {}) {
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  return SecurityScoreSnapshot.find({ scannedAt: { $gte: since } }).sort({ scannedAt: 1 }).lean();
}
