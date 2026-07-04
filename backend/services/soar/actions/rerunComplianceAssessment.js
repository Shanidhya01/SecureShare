/**
 * Phase 10 (Compliance & Governance) SOAR action: the "Re-run Assessment" step of the Compliance
 * Failure Response playbook, and the lightweight recheck attached directly to DLP/malware/threat
 * triggers for continuous compliance (see services/soar/seedPlaybooks.js's
 * ensureAdditionalComplianceAutomation()). Unlike generateComplianceReport.js, this does not also
 * create a ComplianceReport record - it's meant to run cheaply and often.
 */
import { runAssessment } from "../../compliance/complianceEngine.js";

export default async function rerunComplianceAssessment(params, event) {
  const result = await runAssessment({ frameworkKey: params?.frameworkKey, owner: event.owner });
  return { success: true, detail: `Compliance re-assessed (overall score ${result.overallScore}, risk score ${result.riskScore})` };
}
