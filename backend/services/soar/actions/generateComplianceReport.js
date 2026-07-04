/**
 * Phase 10 (Compliance & Governance) SOAR action: triggered by the COMPLIANCE_SCORE_DROP rule.
 * Runs a fresh compliance assessment and records a ComplianceReport audit entry - mirrors
 * generateAuditLog.js's pattern of an action that produces a durable governance record rather
 * than acting on the triggering file/session.
 */
import { runAssessment } from "../../compliance/complianceEngine.js";
import ComplianceReport from "../../../models/ComplianceReport.js";

export default async function generateComplianceReport(params, event) {
  const result = await runAssessment({ owner: event.owner });

  const report = await ComplianceReport.create({
    format: "JSON",
    frameworks: result.frameworks.map((f) => f.framework),
    overallScore: result.overallScore,
    summary: { frameworkScores: result.frameworks, triggeredBy: "soar" },
    generatedBy: event.owner,
    filename: `compliance-report-${Date.now()}.json`
  });

  return { success: true, detail: `Compliance report generated (score ${result.overallScore})`, reportId: report._id };
}
