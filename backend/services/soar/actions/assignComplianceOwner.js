/**
 * Phase 10 (Compliance & Governance) SOAR action: the "Assign Owner" step of the Compliance
 * Failure Response playbook - assigns the currently-failing ComplianceControl documents to a
 * reviewer (params.ownerId, falling back to the triggering event's owner) so there's a named
 * person accountable for remediation, mirroring markFileHighRisk.js's "annotate the affected
 * record" pattern rather than acting on the file/session the triggering event carries.
 */
import ComplianceAssessment from "../../../models/ComplianceAssessment.js";
import ComplianceControl from "../../../models/ComplianceControl.js";

export default async function assignComplianceOwner(params, event) {
  const ownerId = params?.ownerId || event.owner;
  if (!ownerId) return { success: false, detail: "No owner id available to assign" };

  const recentFailures = await ComplianceAssessment.find({ status: "FAIL" })
    .sort({ evaluatedAt: -1 })
    .limit(params?.limit || 20)
    .select("control")
    .lean();

  const controlIds = [...new Set(recentFailures.map((a) => String(a.control)))];
  if (controlIds.length === 0) return { success: true, detail: "No failing controls to assign" };

  await ComplianceControl.updateMany({ _id: { $in: controlIds } }, { owner: ownerId });

  return { success: true, detail: `Assigned ${controlIds.length} failing control(s) to reviewer ${ownerId}` };
}
