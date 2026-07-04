/**
 * Phase 10 (Compliance & Governance): orchestrates a full (or per-framework) compliance
 * assessment run. Loads controls, builds the shared evidence context once per run, evaluates
 * every control through its evaluatorKey (services/compliance/controlEvaluators.js), persists a
 * ComplianceAssessment + linked ComplianceEvidence per control, computes framework/overall
 * scores, and emits SIEM events via the existing services/siem/siemLogger.js - which itself
 * automatically re-enters the SOAR engine (see soarEngine.js), so a critical control failure or
 * score drop can trigger the "COMPLIANCE_SCORE_DROP" automation rule with zero extra plumbing.
 */
import ComplianceFramework from "../../models/ComplianceFramework.js";
import ComplianceControl from "../../models/ComplianceControl.js";
import ComplianceAssessment from "../../models/ComplianceAssessment.js";
import { EVALUATORS } from "./controlEvaluators.js";
import { buildComplianceContext, collectEvidence, EVALUATOR_SOURCE_TYPE } from "./evidenceCollector.js";
import { computeRiskScore, riskDistribution, buildComplianceTrend } from "./riskScoring.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

const SCORE_DROP_THRESHOLD = 70;

export async function runAssessment({ frameworkKey, owner } = {}) {
  const frameworkFilter = frameworkKey ? { key: frameworkKey } : {};
  const frameworks = await ComplianceFramework.find(frameworkFilter).lean();
  if (frameworks.length === 0) return { overallScore: 100, frameworks: [], assessments: [] };

  const frameworkIds = frameworks.map((f) => f._id);
  const controls = await ComplianceControl.find({ framework: { $in: frameworkIds } }).lean();
  const controlById = new Map(controls.map((c) => [String(c._id), c]));
  const context = await buildComplianceContext();

  const assessments = [];
  let criticalFailure = false;

  for (const control of controls) {
    const evaluator = EVALUATORS[control.evaluatorKey];
    if (!evaluator) continue;

    const result = evaluator(context);
    const evidence = await collectEvidence({
      control,
      sourceType: EVALUATOR_SOURCE_TYPE[control.evaluatorKey] || "SECURITY_EVENT",
      sourceRef: result.details,
      summary: `${control.controlId}: ${result.status} (score ${result.score})`
    });

    const assessment = await ComplianceAssessment.create({
      control: control._id,
      framework: control.framework,
      status: result.status,
      score: result.score,
      evidenceRefs: [evidence._id],
      details: result.details,
      recommendations: result.recommendations,
      evaluatedAt: new Date()
    });
    assessments.push(assessment);

    if (result.status === "FAIL" && control.severity === "CRITICAL") criticalFailure = true;

    await logSecurityEvent({
      owner,
      type: result.status === "FAIL" ? "control_failed" : "control_passed",
      message: `Control ${control.controlId} (${control.title}) evaluated: ${result.status}`,
      metadata: { controlId: control.controlId, framework: control.framework, severity: control.severity, score: result.score }
    });
  }

  const overallScore = assessments.length
    ? Math.round(assessments.reduce((sum, a) => sum + a.score, 0) / assessments.length)
    : 100;

  const frameworkScores = frameworks.map((f) => {
    const fAssessments = assessments.filter((a) => String(a.framework) === String(f._id));
    const score = fAssessments.length
      ? Math.round(fAssessments.reduce((sum, a) => sum + a.score, 0) / fAssessments.length)
      : 100;
    return { framework: f.key, name: f.name, score, controlCount: fAssessments.length };
  });

  const bySeverity = assessments.map((a) => ({ status: a.status, severity: controlById.get(String(a.control))?.severity || "MEDIUM", score: a.score, evaluatedAt: a.evaluatedAt }));
  const riskScore = computeRiskScore(bySeverity);
  const failedControls = assessments.filter((a) => a.status === "FAIL").length;
  const passedControls = assessments.filter((a) => a.status === "PASS").length;
  const partialControls = assessments.filter((a) => a.status === "PARTIAL").length;
  const scoreDropped = overallScore < SCORE_DROP_THRESHOLD || criticalFailure;

  await logSecurityEvent({
    owner,
    type: "compliance_scan",
    message: `Compliance scan completed: overall score ${overallScore}`,
    metadata: { overallScore, riskScore, scoreDropped, frameworkScores }
  });

  await logSecurityEvent({
    owner,
    type: scoreDropped ? "compliance_failed" : "compliance_passed",
    message: `Compliance run ${scoreDropped ? "failed" : "passed"} at overall score ${overallScore}`,
    metadata: { overallScore, riskScore, failedControls, passedControls, partialControls }
  });

  return {
    overallScore,
    riskScore,
    riskDistribution: riskDistribution(bySeverity),
    frameworks: frameworkScores,
    assessments,
    failedControls,
    passedControls,
    partialControls
  };
}

/**
 * Historical compliance trend (day-by-day average overall score) over the last `days` days, for
 * the "Compliance Trend"/"Assessment History" dashboard charts. Reads the same ComplianceAssessment
 * history every runAssessment() call already writes - no separate trend-storage collection needed.
 */
export async function getComplianceTrend({ days = 90 } = {}) {
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  const assessments = await ComplianceAssessment.find({ evaluatedAt: { $gte: since } }).select("score evaluatedAt").lean();
  return buildComplianceTrend(assessments);
}
