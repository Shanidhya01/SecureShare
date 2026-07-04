/**
 * Phase 8 (SOAR): seeds a handful of example playbooks + automation rules so the feature is
 * demonstrable out of the box, same pattern as Phase 7's ensureSeedRules() for YARA. Only runs
 * once - skipped if any Playbook already exists, so admin edits/deletes are never overwritten on
 * restart.
 */
import Playbook from "../../models/Playbook.js";
import AutomationRule from "../../models/AutomationRule.js";

export async function ensureSeedPlaybooks() {
  const count = await Playbook.countDocuments();
  if (count > 0) {
    // Playbooks already seeded on a prior deploy - top up the Phase 10 continuation's playbook/
    // rules without touching anything an admin may have since edited, same idempotent-top-up
    // pattern as services/compliance/seedFrameworks.js's ensureAdditionalControls().
    await ensureAdditionalComplianceAutomation();
    await ensureAdditionalCloudAutomation();
    return;
  }

  const playbooks = await Playbook.insertMany([
    {
      name: "Malware Response",
      description: "Quarantines the file, marks it high risk, and notifies the owner when malware is detected.",
      category: "Malware Response",
      steps: [
        { type: "quarantineFile", params: {}, continueOnFailure: true },
        { type: "markFileHighRisk", params: {}, continueOnFailure: true },
        { type: "notifyUser", params: { title: "Malware detected", severity: "CRITICAL" }, continueOnFailure: true },
        { type: "generateAuditLog", params: { message: "Malware Response playbook executed" }, continueOnFailure: true }
      ]
    },
    {
      name: "Credential Leak Response",
      description: "Revokes the compromised session, logs the user out everywhere, and notifies them.",
      category: "Credential Leak Response",
      steps: [
        { type: "revokeSession", params: {}, continueOnFailure: true },
        { type: "logoutUser", params: {}, continueOnFailure: true },
        { type: "notifyUser", params: { title: "Session security alert", severity: "HIGH" }, continueOnFailure: true }
      ]
    },
    {
      name: "DLP Response",
      description: "Blocks the download and notifies the owner when a DLP block decision fires.",
      category: "DLP Response",
      steps: [
        { type: "blockDownload", params: {}, continueOnFailure: true },
        { type: "notifyUser", params: { title: "Sensitive data blocked", severity: "MEDIUM" }, continueOnFailure: true },
        { type: "generateAuditLog", params: { message: "DLP Response playbook executed" }, continueOnFailure: true }
      ]
    },
    {
      name: "Suspicious Device Response",
      description: "Disables the new/suspicious device and notifies the owner.",
      category: "Suspicious Device Response",
      steps: [
        { type: "disableDevice", params: {}, continueOnFailure: true },
        { type: "notifyUser", params: { title: "New device flagged", severity: "MEDIUM" }, continueOnFailure: true }
      ]
    },
    {
      name: "Known Malicious IOC Response",
      description: "Quarantines the file, raises an incident, and alerts administrators for a confirmed IOC match.",
      category: "Known Malicious IOC Response",
      steps: [
        { type: "quarantineFile", params: {}, continueOnFailure: true },
        { type: "raiseIncident", params: { title: "Known malicious IOC matched", severity: "CRITICAL" }, continueOnFailure: true },
        { type: "notifyAdmin", params: { title: "Malicious IOC detected", severity: "CRITICAL" }, continueOnFailure: true }
      ]
    },
    {
      name: "Account Lockdown Response",
      description: "Phase 9: forces an MFA step-up on the account's next login and notifies the owner after repeated failed login attempts.",
      category: "Account Lockdown Response",
      steps: [
        { type: "requireMfaStepUp", params: {}, continueOnFailure: true },
        { type: "notifyUser", params: { title: "Repeated failed login attempts detected", severity: "HIGH" }, continueOnFailure: true }
      ]
    },
    {
      name: "Critical Risk Response",
      description: "Phase 9.5: forces an MFA step-up, raises an incident, and notifies the owner for impossible-travel or otherwise Critical-risk logins.",
      category: "Critical Risk Response",
      steps: [
        { type: "requireMfaStepUp", params: {}, continueOnFailure: true },
        { type: "raiseIncident", params: { title: "Critical-risk login detected", severity: "CRITICAL" }, continueOnFailure: true },
        { type: "notifyUser", params: { title: "Unusual sign-in activity detected on your account", severity: "CRITICAL" }, continueOnFailure: true }
      ]
    }
    // "Compliance Failure Response" is created by ensureAdditionalComplianceAutomation() below,
    // called on every ensureSeedPlaybooks() run (not just the first) so it's a single source of
    // truth regardless of whether this is a fresh database or one seeded before Phase 10 existed.
  ]);

  const byName = Object.fromEntries(playbooks.map((p) => [p.name, p]));

  await AutomationRule.insertMany([
    { name: "Auto-respond to malware detections", trigger: "THREAT_FOUND", playbookId: byName["Malware Response"]._id, priority: 10 },
    { name: "Auto-respond to YARA matches", trigger: "YARA_MATCH", playbookId: byName["Malware Response"]._id, priority: 10 },
    { name: "Auto-respond to DLP blocks", trigger: "DLP_BLOCK", playbookId: byName["DLP Response"]._id, priority: 20 },
    { name: "Auto-respond to signature failures", trigger: "SIGNATURE_FAILED", playbookId: byName["Credential Leak Response"]._id, priority: 20 },
    { name: "Auto-respond to new devices", trigger: "NEW_DEVICE", playbookId: byName["Suspicious Device Response"]._id, priority: 50, enabled: false },
    { name: "Auto-respond to known malicious IOCs", trigger: "IOC_MATCH", playbookId: byName["Known Malicious IOC Response"]._id, priority: 10 },
    { name: "Auto-respond to critical MITRE techniques", trigger: "MITRE_CRITICAL", playbookId: byName["Known Malicious IOC Response"]._id, priority: 10 },
    { name: "Auto-respond to repeated failed logins", trigger: "MULTIPLE_FAILED_LOGINS", playbookId: byName["Account Lockdown Response"]._id, priority: 10 },
    { name: "Auto-respond to impossible travel", trigger: "IMPOSSIBLE_TRAVEL", playbookId: byName["Critical Risk Response"]._id, priority: 5 },
    { name: "Auto-respond to critical-risk logins", trigger: "CRITICAL_RISK_LOGIN", playbookId: byName["Critical Risk Response"]._id, priority: 5 }
    // "Auto-respond to compliance score drops" and the continuous-compliance recheck rules are
    // created by ensureAdditionalComplianceAutomation() below, called on every start (not just
    // the first) so they're also picked up on databases that seeded before Phase 10 existed.
  ]);

  await ensureAdditionalComplianceAutomation();
  await ensureAdditionalCloudAutomation();
}

/**
 * Phase 11 (CSPM/ASM): idempotently ensures a "Cloud Exposure Response" playbook (and its
 * PUBLIC_EXPOSURE_CRITICAL/CERTIFICATE_EXPIRED/CLOUD_SCORE_DROP rules) exist, called on every
 * ensureSeedPlaybooks() run - same guarded-insert pattern as
 * ensureAdditionalComplianceAutomation() above.
 */
async function ensureAdditionalCloudAutomation() {
  let playbook = await Playbook.findOne({ name: "Cloud Exposure Response" });
  if (!playbook) {
    playbook = await Playbook.create({
      name: "Cloud Exposure Response",
      description: "Phase 11: raises an incident, notifies admins, re-runs the cloud scan, and generates a report when a critical public exposure, expired certificate, or cloud score drop is detected.",
      category: "Cloud Exposure Response",
      steps: [
        { type: "raiseIncident", params: { title: "Cloud security exposure detected", severity: "HIGH" }, continueOnFailure: true },
        { type: "notifyAdmin", params: { title: "Cloud security exposure detected", severity: "HIGH" }, continueOnFailure: true },
        { type: "rerunCloudScan", params: {}, continueOnFailure: true },
        { type: "generateCloudReport", params: {}, continueOnFailure: true }
      ]
    });
  }

  const additionalRules = [
    { name: "Auto-respond to critical public exposure", trigger: "PUBLIC_EXPOSURE_CRITICAL", playbookId: playbook._id, priority: 10 },
    { name: "Auto-respond to expired certificates", trigger: "CERTIFICATE_EXPIRED", playbookId: playbook._id, priority: 10 },
    { name: "Auto-respond to cloud security score drops", trigger: "CLOUD_SCORE_DROP", playbookId: playbook._id, priority: 10 },
    { name: "Recheck compliance after cloud exposure", trigger: "PUBLIC_EXPOSURE_CRITICAL", actions: [{ type: "rerunComplianceAssessment", params: {}, continueOnFailure: true }], priority: 90 }
  ];

  for (const rule of additionalRules) {
    const exists = await AutomationRule.exists({ name: rule.name });
    if (!exists) await AutomationRule.create(rule);
  }
}

/**
 * Phase 10 continuation: idempotently ensures the "Compliance Failure Response" playbook (and its
 * COMPLIANCE_SCORE_DROP rule) exist even on a database that had already seeded Phase 8's original
 * playbooks before Phase 10 existed, plus three lightweight "recheck compliance" rules attached to
 * existing triggers (malware detection, DLP violation, critical MITRE technique / SIEM-critical)
 * for continuous compliance - reuses the triggers those phases already emit, no ruleMatcher.js
 * changes needed. Every insert here is guarded individually so it's safe to call on every start.
 */
async function ensureAdditionalComplianceAutomation() {
  let playbook = await Playbook.findOne({ name: "Compliance Failure Response" });
  if (!playbook) {
    playbook = await Playbook.create({
      name: "Compliance Failure Response",
      description: "Phase 10: raises an incident, notifies admins, assigns the failing controls to a reviewer, and re-runs the assessment when overall compliance score drops or a CRITICAL control fails.",
      category: "Compliance Failure Response",
      steps: [
        { type: "raiseIncident", params: { title: "Compliance score dropped", severity: "HIGH" }, continueOnFailure: true },
        { type: "notifyAdmin", params: { title: "Compliance failure detected", severity: "HIGH" }, continueOnFailure: true },
        { type: "assignComplianceOwner", params: {}, continueOnFailure: true },
        { type: "rerunComplianceAssessment", params: {}, continueOnFailure: true }
      ]
    });
  }

  const additionalRules = [
    { name: "Auto-respond to compliance score drops", trigger: "COMPLIANCE_SCORE_DROP", playbookId: playbook._id, priority: 10 },
    { name: "Recheck compliance after malware detection", trigger: "THREAT_FOUND", actions: [{ type: "rerunComplianceAssessment", params: {}, continueOnFailure: true }], priority: 90 },
    { name: "Recheck compliance after DLP violation", trigger: "DLP_BLOCK", actions: [{ type: "rerunComplianceAssessment", params: {}, continueOnFailure: true }], priority: 90 },
    { name: "Recheck compliance after critical MITRE technique", trigger: "MITRE_CRITICAL", actions: [{ type: "rerunComplianceAssessment", params: {}, continueOnFailure: true }], priority: 90 }
  ];

  for (const rule of additionalRules) {
    const exists = await AutomationRule.exists({ name: rule.name });
    if (!exists) await AutomationRule.create(rule);
  }
}
