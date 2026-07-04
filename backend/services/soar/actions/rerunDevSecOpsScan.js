/**
 * Phase 12 (DevSecOps/Supply Chain) SOAR action: "Trigger Rescan" step - re-runs the full
 * DevSecOps scan orchestrator. Mirrors services/soar/actions/rerunCloudScan.js's pattern.
 */
import { runDevSecOpsScan } from "../../devsecops/devSecOpsOrchestrator.js";

export default async function rerunDevSecOpsScan(params, event) {
  const result = await runDevSecOpsScan({ owner: event.owner, checkLiveDependencies: false });
  return { success: true, detail: `DevSecOps scan re-run (overall score ${result.score.overallScore})` };
}
