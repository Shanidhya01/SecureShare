/**
 * Phase 11 (CSPM/ASM) SOAR action: "Run Security Scan" step - re-runs the full cloud scan
 * orchestrator. Mirrors rerunComplianceAssessment.js's pattern of a cheap, frequently-triggered
 * recheck rather than a durable report record.
 */
import { runCloudScan } from "../../cloud/cloudScanOrchestrator.js";

export default async function rerunCloudScan(params, event) {
  const result = await runCloudScan({ owner: event.owner });
  return { success: true, detail: `Cloud scan re-run (overall score ${result.score.overallScore})` };
}
