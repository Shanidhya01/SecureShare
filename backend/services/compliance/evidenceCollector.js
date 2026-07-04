/**
 * Phase 10 (Compliance & Governance): DB-touching evidence collection. Builds the plain `context`
 * object consumed by controlEvaluators.js, and writes ComplianceEvidence docs linking each source
 * to the control(s) it supports. Deliberately org-wide (no `owner` filter) - like SOAR's
 * AutomationRule/Playbook config, compliance is a governance concern over the whole platform, not
 * a per-user view (see backend/controllers/soar.controller.js's rules/playbooks listing for the
 * same pattern).
 */
import User from "../../models/User.js";
import File from "../../models/File.js";
import Device from "../../models/Device.js";
import SecurityEvent from "../../models/SecurityEvent.js";
import Incident from "../../models/Incident.js";
import AutomationRule from "../../models/AutomationRule.js";
import AutomationExecution from "../../models/AutomationExecution.js";
import { getPolicy } from "../../models/SecurityPolicy.js";
import ComplianceEvidence from "../../models/ComplianceEvidence.js";
import { getCurrentPolicyValues } from "./policyEvaluator.js";

const DAY_MS = 24 * 60 * 60 * 1000;

export async function buildComplianceContext() {
  const since30d = new Date(Date.now() - 30 * DAY_MS);
  const since90d = new Date(Date.now() - 90 * DAY_MS);

  const [
    totalFiles, encryptedFiles,
    totalUsers, mfaEnabledUsers,
    threatsDetected, threatsQuarantined,
    scansRun, malwareFound, malwareBlocked,
    dlpViolationsTotal, dlpViolationsBlocked,
    zeroTrustDenied, zeroTrustAllowed,
    eventsLogged30d,
    totalIncidents, resolvedIncidents,
    iocLookups30d, iocMatches30d,
    enabledRules, executions30d, failedExecutions30d,
    securityPolicy, compliancePolicyValues,
    roleAssignedUsers, privilegedUsers, activeUsers90d,
    totalDevices, trustedDevices, revokedDevices,
    riskEventsTotal, highRiskChallenged,
    signedFiles, hashedFiles
  ] = await Promise.all([
    File.countDocuments(),
    File.countDocuments({ encryptionVersion: { $gte: 2 } }),
    User.countDocuments(),
    User.countDocuments({ "mfa.enabled": true }),
    SecurityEvent.countDocuments({ type: { $in: ["threat_found", "ioc_match", "threat_intel_match", "yara_match"] } }),
    File.countDocuments({ quarantined: true }),
    SecurityEvent.countDocuments({ type: { $in: ["threat_found"] }, createdAt: { $gte: since30d } }),
    File.countDocuments({ riskLevel: { $in: ["High", "Critical"] } }),
    File.countDocuments({ riskLevel: { $in: ["High", "Critical"] }, quarantined: true }),
    SecurityEvent.countDocuments({ type: { $in: ["dlp_blocked", "dlp_warning"] } }),
    SecurityEvent.countDocuments({ type: "dlp_blocked" }),
    SecurityEvent.countDocuments({ type: "download_denied" }),
    SecurityEvent.countDocuments({ type: "download_allowed" }),
    SecurityEvent.countDocuments({ createdAt: { $gte: since30d } }),
    Incident.countDocuments(),
    Incident.countDocuments({ status: "resolved" }),
    SecurityEvent.countDocuments({ type: "ioc_lookup", createdAt: { $gte: since30d } }),
    SecurityEvent.countDocuments({ type: { $in: ["ioc_match", "threat_intel_match"] }, createdAt: { $gte: since30d } }),
    AutomationRule.countDocuments({ enabled: true }),
    AutomationExecution.countDocuments({ createdAt: { $gte: since30d } }),
    AutomationExecution.countDocuments({ status: "failed", createdAt: { $gte: since30d } }),
    getPolicy(),
    getCurrentPolicyValues(),
    User.countDocuments({ role: { $exists: true, $ne: null } }),
    User.countDocuments({ role: { $in: ["administrator", "org_owner"] } }),
    SecurityEvent.distinct("owner", { type: "login", createdAt: { $gte: since90d } }),
    Device.countDocuments(),
    Device.countDocuments({ trusted: true, revoked: false }),
    Device.countDocuments({ revoked: true }),
    SecurityEvent.countDocuments({ type: "login", "metadata.riskLevel": { $in: ["High", "Critical"] } }),
    SecurityEvent.countDocuments({ type: "step_up_auth" }),
    File.countDocuments({ signature: { $exists: true, $ne: null } }),
    File.countDocuments({ fileHash: { $exists: true, $ne: null } })
  ]);

  const inactiveUsers90d = Math.max(0, totalUsers - activeUsers90d.length);

  return {
    encryption: { totalFiles, encryptedFiles },
    mfa: { totalUsers, mfaEnabledUsers, requireMFA: !!securityPolicy.requireMFA },
    threatDetection: { threatsDetected, threatsQuarantined },
    malwareProtection: { scansRun, malwareFound, malwareBlocked },
    dlp: { enforcement: !!compliancePolicyValues.DLP_ENFORCEMENT, violationsBlocked: dlpViolationsBlocked, violationsTotal: dlpViolationsTotal },
    zeroTrust: {
      policyChecksTotal: zeroTrustDenied + zeroTrustAllowed,
      policyChecksPassed: zeroTrustAllowed,
      blockUntrustedDevices: !!securityPolicy.blockUntrustedDevices
    },
    auditLogging: { eventsLogged30d },
    sessionManagement: {
      sessionTimeoutMinutes: securityPolicy.sessionTimeoutMinutes || 0,
      maxSessions: securityPolicy.maxSessions || 0
    },
    incidentResponse: { totalIncidents, resolvedIncidents, avgResponseDurationMs: null },
    threatIntel: { iocLookups30d, iocMatches30d },
    soarAutomation: { enabledRules, executions30d, failedExecutions30d },
    passwordPolicy: {
      minPasswordLength: securityPolicy.minPasswordLength || 0,
      requirePasswordComplexity: !!securityPolicy.requirePasswordComplexity,
      passwordExpiryDays: securityPolicy.passwordExpiryDays || 0
    },
    identity: { totalUsers, roleAssignedUsers, privilegedUsers, inactiveUsers90d },
    deviceTrust: { totalDevices, trustedDevices, revokedDevices },
    adaptiveAuth: { riskEventsTotal, highRiskChallenged },
    digitalSignature: { totalFiles, signedFiles },
    fileIntegrity: { totalFiles, hashedFiles },
    _raw: { securityPolicy, compliancePolicyValues }
  };
}

/** Persists a ComplianceEvidence doc for a control's assessment, sourced from the context above. */
export async function collectEvidence({ control, sourceType, sourceRef, summary }) {
  return ComplianceEvidence.create({ control: control?._id || control, sourceType, sourceRef, summary });
}

/** Maps an evaluatorKey to the ComplianceEvidence sourceType it's primarily backed by. */
export const EVALUATOR_SOURCE_TYPE = {
  encryptionEvaluator: "FILE_METADATA",
  mfaEvaluator: "IDENTITY",
  threatDetectionEvaluator: "SECURITY_EVENT",
  malwareProtectionEvaluator: "FILE_METADATA",
  dlpEvaluator: "SECURITY_EVENT",
  zeroTrustEvaluator: "SECURITY_EVENT",
  auditLoggingEvaluator: "SIEM",
  sessionManagementEvaluator: "POLICY",
  incidentResponseEvaluator: "INCIDENT",
  threatIntelEvaluator: "THREAT_INTEL",
  soarAutomationEvaluator: "SOAR",
  passwordPolicyEvaluator: "POLICY",
  identityEvaluator: "IDENTITY",
  deviceTrustEvaluator: "IDENTITY",
  adaptiveAuthEvaluator: "SECURITY_EVENT",
  digitalSignatureEvaluator: "FILE_METADATA",
  fileIntegrityEvaluator: "FILE_METADATA"
};
