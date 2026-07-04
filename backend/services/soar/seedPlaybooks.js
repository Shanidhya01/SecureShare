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
  if (count > 0) return;

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
  ]);
}
