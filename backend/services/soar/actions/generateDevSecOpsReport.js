/**
 * Phase 12 (DevSecOps/Supply Chain) SOAR action: "Generate Report" step - mirrors
 * services/soar/actions/generateCloudReport.js's pattern of producing a durable governance record
 * after a scan run.
 */
import { runRiskEngine } from "../../devsecops/riskEngine.js";
import ComplianceReport from "../../../models/ComplianceReport.js";

export default async function generateDevSecOpsReport(params, event) {
  const result = await runRiskEngine({ owner: event.owner });

  const report = await ComplianceReport.create({
    format: "JSON",
    frameworks: ["DEVSECOPS"],
    overallScore: result.overallScore,
    summary: { scores: result, triggeredBy: "soar" },
    generatedBy: event.owner,
    filename: `devsecops-report-${Date.now()}.json`
  });

  return { success: true, detail: `DevSecOps report generated (score ${result.overallScore})`, reportId: report._id };
}
