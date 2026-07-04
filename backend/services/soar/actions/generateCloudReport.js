/**
 * Phase 11 (CSPM/ASM) SOAR action: "Generate Report" step - mirrors generateComplianceReport.js's
 * pattern of producing a durable governance record after a scan run.
 */
import { runScoreEngine } from "../../cloud/scoreEngine.js";
import ComplianceReport from "../../../models/ComplianceReport.js";

export default async function generateCloudReport(params, event) {
  const result = await runScoreEngine({ owner: event.owner });

  const report = await ComplianceReport.create({
    format: "JSON",
    frameworks: ["CLOUD_SECURITY"],
    overallScore: result.overallScore,
    summary: { scores: result, triggeredBy: "soar" },
    generatedBy: event.owner,
    filename: `cloud-security-report-${Date.now()}.json`
  });

  return { success: true, detail: `Cloud security report generated (score ${result.overallScore})`, reportId: report._id };
}
