import ComplianceFramework from "../models/ComplianceFramework.js";
import ComplianceControl from "../models/ComplianceControl.js";
import ComplianceAssessment from "../models/ComplianceAssessment.js";
import ComplianceEvidence from "../models/ComplianceEvidence.js";
import ComplianceReport from "../models/ComplianceReport.js";
import SecurityEvent from "../models/SecurityEvent.js";
import { runAssessment, getComplianceTrend } from "../services/compliance/complianceEngine.js";
import { computeRiskScore, riskDistribution } from "../services/compliance/riskScoring.js";
import {
  listCurrentPolicies,
  setPolicyValue,
  getPolicyHistory,
  rollbackPolicy,
  setPolicyApproval,
  setPolicyVersionEnabled
} from "../services/compliance/policyEvaluator.js";
import { buildCsv, buildJson, buildPdf } from "../services/compliance/reportGenerator.js";
import { logSecurityEvent } from "../services/siem/siemLogger.js";

/* ============================== FRAMEWORKS ============================== */

export const listFrameworks = async (_req, res) => {
  const frameworks = await ComplianceFramework.find().sort({ name: 1 });
  res.json(frameworks);
};

export const getFramework = async (req, res) => {
  const framework = await ComplianceFramework.findById(req.params.id);
  if (!framework) return res.sendStatus(404);
  res.json(framework);
};

/** PATCH /frameworks/:id - enable/disable a framework (e.g. drop it from active assessments). */
export const updateFramework = async (req, res) => {
  const { enabled } = req.body || {};
  const update = {};
  if (typeof enabled === "boolean") update.enabled = enabled;

  const framework = await ComplianceFramework.findByIdAndUpdate(req.params.id, update, { new: true });
  if (!framework) return res.sendStatus(404);

  await logSecurityEvent({
    owner: req.user.id,
    type: "framework_updated",
    message: `Compliance framework "${framework.name}" updated`,
    metadata: { frameworkId: framework._id, key: framework.key, enabled: framework.enabled }
  });

  res.json(framework);
};

/* ============================== CONTROLS ============================== */

export const listControls = async (req, res) => {
  const filter = {};
  if (req.query.framework) filter.framework = req.query.framework;
  if (req.query.category) filter.category = req.query.category;
  const controls = await ComplianceControl.find(filter).populate("framework", "key name").sort({ controlId: 1 });
  res.json(controls);
};

export const getControl = async (req, res) => {
  const control = await ComplianceControl.findById(req.params.id).populate("framework", "key name");
  if (!control) return res.sendStatus(404);
  res.json(control);
};

/* ============================== ASSESSMENTS ============================== */

export const listAssessments = async (req, res) => {
  const filter = {};
  if (req.query.framework) filter.framework = req.query.framework;
  if (req.query.status) filter.status = req.query.status;
  const assessments = await ComplianceAssessment.find(filter)
    .populate("control", "controlId title category severity")
    .populate("framework", "key name")
    .sort({ evaluatedAt: -1 })
    .limit(500);
  res.json(assessments);
};

/** GET /findings - open findings (FAIL/PARTIAL) across every control's latest assessment. */
export const getFindings = async (req, res) => {
  const filter = { status: { $in: ["FAIL", "PARTIAL"] } };
  if (req.query.framework) filter.framework = req.query.framework;

  const findings = await ComplianceAssessment.find(filter)
    .populate("control", "controlId title category severity recommendation")
    .populate("framework", "key name")
    .sort({ evaluatedAt: -1 })
    .limit(500);
  res.json(findings);
};

export const runScan = async (req, res) => {
  const result = await runAssessment({ frameworkKey: req.body?.frameworkKey, owner: req.user.id });
  res.json(result);
};

/* ============================== EVIDENCE ============================== */

export const listEvidence = async (req, res) => {
  const filter = {};
  if (req.query.control) filter.control = req.query.control;
  if (req.query.sourceType) filter.sourceType = req.query.sourceType;
  const evidence = await ComplianceEvidence.find(filter)
    .populate("control", "controlId title")
    .sort({ collectedAt: -1 })
    .limit(500);
  res.json(evidence);
};

export const approveEvidence = async (req, res) => {
  const evidence = await ComplianceEvidence.findByIdAndUpdate(
    req.params.id,
    { approved: true, approvedBy: req.user.id },
    { new: true }
  );
  if (!evidence) return res.sendStatus(404);
  res.json(evidence);
};

/* ============================== POLICIES ============================== */

export const listPolicies = async (_req, res) => {
  const policies = await listCurrentPolicies();
  res.json(policies);
};

export const updatePolicy = async (req, res) => {
  const { name } = req.params;
  const { value, enabled } = req.body || {};

  let policy;
  try {
    policy = await setPolicyValue({ name, value, enabled, updatedBy: req.user.id });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  await logSecurityEvent({
    owner: req.user.id,
    type: "policy_updated",
    message: `Compliance policy "${name}" updated to version ${policy.version}`,
    metadata: { name, value, version: policy.version }
  });

  res.json(policy);
};

/** POST /policies - create the first (or a fresh) version of a governance policy. Uses the same
 *  versioned setPolicyValue() as updatePolicy - "create" and "update" are the same operation on a
 *  policy that's always append-only. */
export const createPolicy = async (req, res) => {
  const { name, value, enabled } = req.body || {};
  if (!name) return res.status(400).json({ error: "name is required" });

  let policy;
  try {
    policy = await setPolicyValue({ name, value, enabled, updatedBy: req.user.id });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  await logSecurityEvent({
    owner: req.user.id,
    type: "policy_updated",
    message: `Compliance policy "${name}" created (version ${policy.version})`,
    metadata: { name, value, version: policy.version }
  });

  res.status(201).json(policy);
};

/** PATCH /policies/:id - enable/disable or set the approval status of one specific version
 *  document directly (by _id), without creating a new version. */
export const patchPolicyById = async (req, res) => {
  const { enabled, approvalStatus } = req.body || {};
  let policy = null;

  if (typeof enabled === "boolean") {
    policy = await setPolicyVersionEnabled({ id: req.params.id, enabled });
    if (!policy) return res.sendStatus(404);
  }
  if (approvalStatus) {
    policy = await setPolicyApproval({ id: req.params.id, status: approvalStatus, approvedBy: req.user.id });
    if (!policy) return res.sendStatus(404);
  }
  if (!policy) return res.status(400).json({ error: "Provide `enabled` and/or `approvalStatus` to update" });

  await logSecurityEvent({
    owner: req.user.id,
    type: "policy_updated",
    message: `Compliance policy "${policy.name}" v${policy.version} updated`,
    metadata: { name: policy.name, version: policy.version, enabled: policy.enabled, approvalStatus: policy.approvalStatus }
  });

  res.json(policy);
};

/** GET /policies/:name/history - full version history for one governance policy. */
export const getPolicyHistoryEndpoint = async (req, res) => {
  const history = await getPolicyHistory(req.params.name);
  res.json(history);
};

/** POST /policies/:name/rollback/:version - re-activate an older version's value as a new version. */
export const rollbackPolicyEndpoint = async (req, res) => {
  const { name, version } = req.params;
  let policy;
  try {
    policy = await rollbackPolicy({ name, version: Number(version), updatedBy: req.user.id });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  await logSecurityEvent({
    owner: req.user.id,
    type: "policy_updated",
    message: `Compliance policy "${name}" rolled back to the value from version ${version} (now version ${policy.version})`,
    metadata: { name, rolledBackFrom: Number(version), newVersion: policy.version }
  });

  res.json(policy);
};

/* ============================== REPORTS ============================== */

export const listReports = async (_req, res) => {
  const reports = await ComplianceReport.find().populate("generatedBy", "name email").sort({ createdAt: -1 }).limit(100);
  res.json(reports);
};

/**
 * Shared by POST/GET /reports (with ?format=) and the dedicated GET /export/pdf|csv|json routes
 * - `format` can be passed explicitly (from the export/:format route param) or read from the
 * query/body as before, so both URL styles hit the same generation logic.
 */
export const generateReport = async (req, res) => {
  const format = (req.params.format || req.query.format || req.body?.format || "json").toUpperCase();
  const frameworkKey = req.query.frameworkKey || req.body?.frameworkKey;

  const result = await runAssessment({ frameworkKey, owner: req.user.id });

  const controls = await ComplianceControl.find({ _id: { $in: result.assessments.map((a) => a.control) } }).lean();
  const controlById = new Map(controls.map((c) => [String(c._id), c]));
  const frameworks = await ComplianceFramework.find({ _id: { $in: result.assessments.map((a) => a.framework) } }).lean();
  const frameworkById = new Map(frameworks.map((f) => [String(f._id), f]));

  const assessments = result.assessments.map((a) => {
    const control = controlById.get(String(a.control));
    const framework = frameworkById.get(String(a.framework));
    return {
      frameworkKey: framework?.key,
      controlId: control?.controlId,
      title: control?.title,
      category: control?.category,
      severity: control?.severity,
      status: a.status,
      score: a.score,
      recommendations: a.recommendations,
      evaluatedAt: a.evaluatedAt
    };
  });

  const generatedAt = new Date();
  const filename = `compliance-report-${Date.now()}.${format.toLowerCase()}`;

  const trend = await getComplianceTrend({ days: 90 });

  await ComplianceReport.create({
    format,
    frameworks: result.frameworks.map((f) => f.framework),
    overallScore: result.overallScore,
    summary: { frameworkScores: result.frameworks, riskScore: result.riskScore },
    generatedBy: req.user.id,
    filename
  });

  await logSecurityEvent({
    owner: req.user.id,
    type: "report_generated",
    message: `Compliance report generated (${format})`,
    metadata: { format, overallScore: result.overallScore, riskScore: result.riskScore }
  });

  const reportPayload = {
    overallScore: result.overallScore,
    riskScore: result.riskScore,
    riskDistribution: result.riskDistribution,
    frameworkScores: result.frameworks,
    assessments,
    trend,
    generatedAt
  };

  if (format === "PDF") {
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    return buildPdf(reportPayload, res);
  }

  if (format === "CSV") {
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    return res.send(buildCsv(reportPayload));
  }

  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  return res.json(buildJson(reportPayload));
};

/* ============================== DASHBOARD ============================== */

export const getDashboard = async (_req, res) => {
  const [frameworks, controls, latestAssessments, openFindings, evidenceCount, policies, recentReports, trend, policyViolations30d, auditActivity30d] = await Promise.all([
    ComplianceFramework.find().lean(),
    ComplianceControl.find().select("severity").lean(),
    ComplianceAssessment.find().sort({ evaluatedAt: -1 }).limit(1000).lean(),
    ComplianceAssessment.find({ status: "FAIL" }).populate("control", "controlId title severity").populate("framework", "key name").sort({ evaluatedAt: -1 }).limit(50),
    ComplianceEvidence.countDocuments(),
    listCurrentPolicies(),
    ComplianceReport.find().sort({ createdAt: -1 }).limit(10),
    getComplianceTrend({ days: 90 }),
    SecurityEvent.countDocuments({ type: "compliance_policy_violation", createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } }),
    SecurityEvent.countDocuments({ category: "COMPLIANCE", createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } })
  ]);

  const severityByControl = new Map(controls.map((c) => [String(c._id), c.severity]));

  // Keep only the most recent assessment per control for "current state" aggregates.
  const latestByControl = new Map();
  for (const a of latestAssessments) {
    const key = String(a.control);
    if (!latestByControl.has(key)) latestByControl.set(key, a);
  }
  const currentAssessments = Array.from(latestByControl.values());

  const overallScore = currentAssessments.length
    ? Math.round(currentAssessments.reduce((sum, a) => sum + a.score, 0) / currentAssessments.length)
    : 100;

  const frameworkStatus = frameworks.map((f) => {
    const frameworkAssessments = currentAssessments.filter((a) => String(a.framework) === String(f._id));
    const score = frameworkAssessments.length
      ? Math.round(frameworkAssessments.reduce((sum, a) => sum + a.score, 0) / frameworkAssessments.length)
      : 100;
    return { framework: f.key, name: f.name, score, controlCount: frameworkAssessments.length, enabled: f.enabled };
  });

  const controlCoverage = {
    PASS: currentAssessments.filter((a) => a.status === "PASS").length,
    FAIL: currentAssessments.filter((a) => a.status === "FAIL").length,
    PARTIAL: currentAssessments.filter((a) => a.status === "PARTIAL").length,
    NOT_APPLICABLE: currentAssessments.filter((a) => a.status === "NOT_APPLICABLE").length
  };

  const recommendations = Array.from(
    new Set(currentAssessments.flatMap((a) => a.recommendations || []))
  ).slice(0, 20);

  const bySeverity = currentAssessments.map((a) => ({ status: a.status, severity: severityByControl.get(String(a.control)) || "MEDIUM" }));
  const riskScore = computeRiskScore(bySeverity);

  res.json({
    overallScore,
    riskScore,
    riskDistribution: riskDistribution(bySeverity),
    frameworkStatus,
    controlCoverage,
    openFindings,
    recentAssessments: currentAssessments.slice(0, 20),
    evidenceCount,
    policies,
    recentReports,
    recommendations,
    trend,
    policyViolations30d,
    auditActivity30d
  });
};
