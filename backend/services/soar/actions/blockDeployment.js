/**
 * Phase 12 (DevSecOps/Supply Chain) SOAR action: "Block Deployment" step. There is no real CD
 * system in this project to gate, so this is honestly an *advisory* block - it marks the
 * triggering finding as acknowledged with a `deploymentBlocked` metadata flag and logs the event,
 * rather than pretending to halt a pipeline that doesn't exist here.
 */
import DevSecOpsFinding from "../../../models/DevSecOpsFinding.js";

export default async function blockDeployment(params, event) {
  const findingId = event.metadata?.findingId || event.metadata?.ruleId;
  if (event.metadata?.ruleId) {
    await DevSecOpsFinding.updateMany(
      { ruleId: event.metadata.ruleId, status: "open" },
      { $set: { "metadata.deploymentBlocked": true, "metadata.deploymentBlockedAt": new Date() } }
    );
  }

  return { success: true, detail: `Deployment advisory block recorded for finding "${findingId || "unknown"}" - no live CI/CD system is configured to enforce this automatically.` };
}
