/**
 * Phase 10 (Compliance & Governance): pure, DB-free control evaluators - mirrors the
 * services/soar/ruleMatcher.js convention so every evaluator is directly unit testable (see
 * backend/tests/compliance.test.js) without touching Mongo. Each function takes the plain
 * `context` object built by services/compliance/evidenceCollector.js and returns
 * `{ status, score, severity, details, evidence, recommendations }` - the `_impl` functions below
 * compute the core `{ status, score, details, recommendations }` verdict; `withEvaluatorMeta()`
 * derives `severity` (from status) and `evidence` (a human-readable summary of `details`) once,
 * so every evaluator gets them without repeating the same boilerplate 17 times.
 *
 * `status` is one of PASS / FAIL / PARTIAL / NOT_APPLICABLE (see models/ComplianceAssessment.js).
 * `score` is 0-100 and feeds the framework/overall compliance scores in complianceEngine.js.
 */

function clampScore(n) {
  return Math.max(0, Math.min(100, Math.round(n)));
}

function verdictFromScore(score, { partialAt = 60, passAt = 85 } = {}) {
  if (score >= passAt) return "PASS";
  if (score >= partialAt) return "PARTIAL";
  return "FAIL";
}

/** Derived, generic severity for a verdict - distinct from a ComplianceControl's own static
 *  `severity` field (which reflects how important the control is regardless of outcome). */
function severityFromStatus(status) {
  switch (status) {
    case "FAIL":
      return "HIGH";
    case "PARTIAL":
      return "MEDIUM";
    default:
      return "INFO"; // PASS / NOT_APPLICABLE
  }
}

function withEvaluatorMeta(fn) {
  return (context) => {
    const result = fn(context);
    const evidence = Object.entries(result.details || {}).map(([key, value]) => `${key}: ${JSON.stringify(value)}`);
    return { ...result, severity: severityFromStatus(result.status), evidence };
  };
}

function encryptionEvaluator_impl(context) {
  const { totalFiles = 0, encryptedFiles = 0 } = context.encryption || {};
  const score = totalFiles === 0 ? 100 : clampScore((encryptedFiles / totalFiles) * 100);
  const status = totalFiles === 0 ? "NOT_APPLICABLE" : verdictFromScore(score, { partialAt: 90, passAt: 100 });
  const recommendations = [];
  if (status !== "PASS" && status !== "NOT_APPLICABLE") {
    recommendations.push("Ensure all stored files use zero-knowledge client-side encryption before upload.");
  }
  return { status, score, details: { totalFiles, encryptedFiles }, recommendations };
}

function mfaEvaluator_impl(context) {
  const { totalUsers = 0, mfaEnabledUsers = 0, requireMFA = false } = context.mfa || {};
  if (totalUsers === 0) return { status: "NOT_APPLICABLE", score: 100, details: { totalUsers }, recommendations: [] };

  const adoptionRate = (mfaEnabledUsers / totalUsers) * 100;
  const score = clampScore(requireMFA ? adoptionRate : Math.max(adoptionRate, 50));
  const status = requireMFA ? verdictFromScore(score, { partialAt: 80, passAt: 100 }) : verdictFromScore(adoptionRate, { partialAt: 30, passAt: 70 });
  const recommendations = [];
  if (!requireMFA) recommendations.push("Enable the organization-wide MFA requirement in Security Policy.");
  if (adoptionRate < 100) recommendations.push("Encourage or enforce MFA enrollment for all remaining users.");
  return { status, score, details: { totalUsers, mfaEnabledUsers, adoptionRate: Math.round(adoptionRate), requireMFA }, recommendations };
}

function threatDetectionEvaluator_impl(context) {
  const { threatsDetected = 0, threatsQuarantined = 0 } = context.threatDetection || {};
  const containmentRate = threatsDetected === 0 ? 100 : (threatsQuarantined / threatsDetected) * 100;
  const score = clampScore(containmentRate);
  const status = threatsDetected === 0 ? "PASS" : verdictFromScore(score, { partialAt: 70, passAt: 95 });
  const recommendations = status !== "PASS" ? ["Investigate detected threats that were not quarantined or blocked."] : [];
  return { status, score, details: { threatsDetected, threatsQuarantined }, recommendations };
}

function malwareProtectionEvaluator_impl(context) {
  const { scansRun = 0, malwareFound = 0, malwareBlocked = 0 } = context.malwareProtection || {};
  const blockRate = malwareFound === 0 ? 100 : (malwareBlocked / malwareFound) * 100;
  const score = clampScore(blockRate);
  const status = malwareFound === 0 ? "PASS" : verdictFromScore(score, { partialAt: 70, passAt: 95 });
  const recommendations = status !== "PASS" ? ["Review malware scanning coverage and ensure ClamAV/YARA rules are current."] : [];
  return { status, score, details: { scansRun, malwareFound, malwareBlocked }, recommendations };
}

function dlpEvaluator_impl(context) {
  const { enforcement = false, violationsBlocked = 0, violationsTotal = 0 } = context.dlp || {};
  if (!enforcement) {
    return {
      status: "FAIL",
      score: 30,
      details: { enforcement, violationsBlocked, violationsTotal },
      recommendations: ["Enable DLP enforcement policy to actively block sensitive data exfiltration."]
    };
  }
  const blockRate = violationsTotal === 0 ? 100 : (violationsBlocked / violationsTotal) * 100;
  const score = clampScore(blockRate);
  const status = verdictFromScore(score, { partialAt: 70, passAt: 95 });
  const recommendations = status !== "PASS" ? ["Review DLP detector coverage for the data types most frequently flagged."] : [];
  return { status, score, details: { enforcement, violationsBlocked, violationsTotal }, recommendations };
}

function zeroTrustEvaluator_impl(context) {
  const { policyChecksTotal = 0, policyChecksPassed = 0, blockUntrustedDevices = false } = context.zeroTrust || {};
  const passRate = policyChecksTotal === 0 ? 100 : (policyChecksPassed / policyChecksTotal) * 100;
  const score = clampScore(blockUntrustedDevices ? passRate : Math.min(passRate, 80));
  const status = verdictFromScore(score, { partialAt: 60, passAt: 90 });
  const recommendations = [];
  if (!blockUntrustedDevices) recommendations.push("Enable blocking of untrusted devices under Security Policy.");
  return { status, score, details: { policyChecksTotal, policyChecksPassed, blockUntrustedDevices }, recommendations };
}

function auditLoggingEvaluator_impl(context) {
  const { eventsLogged30d = 0 } = context.auditLogging || {};
  const score = eventsLogged30d > 0 ? 100 : 40;
  const status = eventsLogged30d > 0 ? "PASS" : "FAIL";
  const recommendations = eventsLogged30d === 0 ? ["No security events recorded in the last 30 days - verify SIEM logging is active."] : [];
  return { status, score, details: { eventsLogged30d }, recommendations };
}

function sessionManagementEvaluator_impl(context) {
  const { sessionTimeoutMinutes = 0, maxSessions = 0 } = context.sessionManagement || {};
  let score = 40;
  if (sessionTimeoutMinutes > 0) score += 30;
  if (maxSessions > 0) score += 30;
  score = clampScore(score);
  const status = verdictFromScore(score, { partialAt: 50, passAt: 90 });
  const recommendations = [];
  if (sessionTimeoutMinutes === 0) recommendations.push("Configure a session idle timeout in Security Policy.");
  if (maxSessions === 0) recommendations.push("Configure a maximum concurrent session limit in Security Policy.");
  return { status, score, details: { sessionTimeoutMinutes, maxSessions }, recommendations };
}

function incidentResponseEvaluator_impl(context) {
  const { totalIncidents = 0, resolvedIncidents = 0, avgResponseDurationMs = null } = context.incidentResponse || {};
  if (totalIncidents === 0) return { status: "PASS", score: 100, details: { totalIncidents }, recommendations: [] };

  const resolutionRate = (resolvedIncidents / totalIncidents) * 100;
  const score = clampScore(resolutionRate);
  const status = verdictFromScore(score, { partialAt: 60, passAt: 90 });
  const recommendations = status !== "PASS" ? ["Investigate and resolve outstanding open security incidents."] : [];
  return { status, score, details: { totalIncidents, resolvedIncidents, avgResponseDurationMs }, recommendations };
}

function threatIntelEvaluator_impl(context) {
  const { iocLookups30d = 0, iocMatches30d = 0 } = context.threatIntel || {};
  const score = iocLookups30d > 0 ? 100 : 50;
  const status = iocLookups30d > 0 ? "PASS" : "PARTIAL";
  const recommendations = iocLookups30d === 0 ? ["No threat intelligence lookups recorded in the last 30 days."] : [];
  return { status, score, details: { iocLookups30d, iocMatches30d }, recommendations };
}

function soarAutomationEvaluator_impl(context) {
  const { enabledRules = 0, executions30d = 0, failedExecutions30d = 0 } = context.soarAutomation || {};
  if (enabledRules === 0) {
    return { status: "FAIL", score: 20, details: { enabledRules }, recommendations: ["Enable at least one SOAR automation rule for incident response."] };
  }
  const successRate = executions30d === 0 ? 100 : ((executions30d - failedExecutions30d) / executions30d) * 100;
  const score = clampScore(successRate);
  const status = verdictFromScore(score, { partialAt: 70, passAt: 95 });
  const recommendations = status !== "PASS" ? ["Review failing SOAR playbook executions and fix broken action steps."] : [];
  return { status, score, details: { enabledRules, executions30d, failedExecutions30d }, recommendations };
}

function passwordPolicyEvaluator_impl(context) {
  const { minPasswordLength = 0, requirePasswordComplexity = false, passwordExpiryDays = 0 } = context.passwordPolicy || {};
  let score = 20;
  if (minPasswordLength >= 8) score += 30;
  else if (minPasswordLength >= 6) score += 15;
  if (requirePasswordComplexity) score += 30;
  if (passwordExpiryDays > 0) score += 20;
  score = clampScore(score);
  const status = verdictFromScore(score, { partialAt: 50, passAt: 85 });
  const recommendations = [];
  if (minPasswordLength < 8) recommendations.push("Raise the minimum password length to at least 8 characters.");
  if (!requirePasswordComplexity) recommendations.push("Require password complexity (upper/lower/digit/symbol).");
  if (passwordExpiryDays === 0) recommendations.push("Configure a password expiry period in Security Policy.");
  return { status, score, details: { minPasswordLength, requirePasswordComplexity, passwordExpiryDays }, recommendations };
}

function identityEvaluator_impl(context) {
  const { totalUsers = 0, roleAssignedUsers = 0, privilegedUsers = 0, inactiveUsers90d = 0 } = context.identity || {};
  if (totalUsers === 0) return { status: "NOT_APPLICABLE", score: 100, details: { totalUsers }, recommendations: [] };

  const roleCoverage = (roleAssignedUsers / totalUsers) * 100;
  const inactiveRate = (inactiveUsers90d / totalUsers) * 100;
  const score = clampScore(roleCoverage - inactiveRate * 0.5);
  const status = verdictFromScore(score, { partialAt: 60, passAt: 90 });
  const recommendations = [];
  if (roleCoverage < 100) recommendations.push("Assign an explicit RBAC role to every user account.");
  if (inactiveUsers90d > 0) recommendations.push(`Review ${inactiveUsers90d} inactive user account(s) for offboarding.`);
  return { status, score, details: { totalUsers, roleAssignedUsers, privilegedUsers, inactiveUsers90d }, recommendations };
}

function deviceTrustEvaluator_impl(context) {
  const { totalDevices = 0, trustedDevices = 0, revokedDevices = 0 } = context.deviceTrust || {};
  if (totalDevices === 0) return { status: "NOT_APPLICABLE", score: 100, details: { totalDevices }, recommendations: [] };

  const trustRate = (trustedDevices / totalDevices) * 100;
  const score = clampScore(trustRate);
  const status = verdictFromScore(score, { partialAt: 60, passAt: 90 });
  const recommendations = status !== "PASS" ? ["Review and revoke untrusted or stale devices."] : [];
  return { status, score, details: { totalDevices, trustedDevices, revokedDevices }, recommendations };
}

function adaptiveAuthEvaluator_impl(context) {
  const { riskEventsTotal = 0, highRiskChallenged = 0 } = context.adaptiveAuth || {};
  if (riskEventsTotal === 0) return { status: "PASS", score: 100, details: { riskEventsTotal }, recommendations: [] };

  const challengeRate = (highRiskChallenged / riskEventsTotal) * 100;
  const score = clampScore(challengeRate);
  const status = verdictFromScore(score, { partialAt: 60, passAt: 90 });
  const recommendations = status !== "PASS" ? ["Ensure high/critical risk logins are consistently challenged with step-up authentication."] : [];
  return { status, score, details: { riskEventsTotal, highRiskChallenged }, recommendations };
}

function digitalSignatureEvaluator_impl(context) {
  const { totalFiles = 0, signedFiles = 0 } = context.digitalSignature || {};
  if (totalFiles === 0) return { status: "NOT_APPLICABLE", score: 100, details: { totalFiles }, recommendations: [] };

  const score = clampScore((signedFiles / totalFiles) * 100);
  const status = verdictFromScore(score, { partialAt: 60, passAt: 95 });
  const recommendations = status !== "PASS" ? ["Sign uploaded files client-side to enable integrity/authenticity verification."] : [];
  return { status, score, details: { totalFiles, signedFiles }, recommendations };
}

function fileIntegrityEvaluator_impl(context) {
  const { totalFiles = 0, hashedFiles = 0 } = context.fileIntegrity || {};
  if (totalFiles === 0) return { status: "NOT_APPLICABLE", score: 100, details: { totalFiles }, recommendations: [] };

  const score = clampScore((hashedFiles / totalFiles) * 100);
  const status = verdictFromScore(score, { partialAt: 60, passAt: 95 });
  const recommendations = status !== "PASS" ? ["Compute and store an integrity hash for every uploaded file."] : [];
  return { status, score, details: { totalFiles, hashedFiles }, recommendations };
}

/** Phase 11 (CSPM/ASM) PART 13: lowers compliance score whenever open cloud security posture
 *  findings exist - an open CRITICAL finding fails the control outright regardless of count. */
function cloudSecurityEvaluator_impl(context) {
  const { openCritical = 0, openHigh = 0, totalOpen = 0 } = context.cloudSecurity || {};
  if (totalOpen === 0) return { status: "PASS", score: 100, details: { openCritical, openHigh, totalOpen }, recommendations: [] };

  if (openCritical > 0) {
    return {
      status: "FAIL",
      score: clampScore(100 - openCritical * 25 - openHigh * 10),
      details: { openCritical, openHigh, totalOpen },
      recommendations: ["Remediate open CRITICAL cloud security posture findings immediately - see the Cloud Security dashboard."]
    };
  }

  const score = clampScore(100 - openHigh * 10 - totalOpen * 2);
  const status = verdictFromScore(score, { partialAt: 60, passAt: 90 });
  const recommendations = status !== "PASS" ? ["Resolve outstanding cloud configuration/exposure findings from the CSPM/ASM scanner."] : [];
  return { status, score, details: { openCritical, openHigh, totalOpen }, recommendations };
}

/** Phase 12 (DevSecOps/Supply Chain) PART 16: lowers compliance score whenever open dependency/
 *  secret/SAST/container/IaC findings exist - mirrors cloudSecurityEvaluator_impl's shape exactly. */
function devSecOpsEvaluator_impl(context) {
  const { openCritical = 0, openHigh = 0, totalOpen = 0 } = context.devSecOps || {};
  if (totalOpen === 0) return { status: "PASS", score: 100, details: { openCritical, openHigh, totalOpen }, recommendations: [] };

  if (openCritical > 0) {
    return {
      status: "FAIL",
      score: clampScore(100 - openCritical * 25 - openHigh * 10),
      details: { openCritical, openHigh, totalOpen },
      recommendations: ["Remediate open CRITICAL DevSecOps findings (secrets, dependencies, container/IaC misconfigurations) immediately - see the DevSecOps dashboard."]
    };
  }

  const score = clampScore(100 - openHigh * 10 - totalOpen * 2);
  const status = verdictFromScore(score, { partialAt: 60, passAt: 90 });
  const recommendations = status !== "PASS" ? ["Resolve outstanding dependency/secret/SAST/container/IaC findings from the DevSecOps scanner."] : [];
  return { status, score, details: { openCritical, openHigh, totalOpen }, recommendations };
}

export const encryptionEvaluator = withEvaluatorMeta(encryptionEvaluator_impl);
export const mfaEvaluator = withEvaluatorMeta(mfaEvaluator_impl);
export const threatDetectionEvaluator = withEvaluatorMeta(threatDetectionEvaluator_impl);
export const malwareProtectionEvaluator = withEvaluatorMeta(malwareProtectionEvaluator_impl);
export const dlpEvaluator = withEvaluatorMeta(dlpEvaluator_impl);
export const zeroTrustEvaluator = withEvaluatorMeta(zeroTrustEvaluator_impl);
export const auditLoggingEvaluator = withEvaluatorMeta(auditLoggingEvaluator_impl);
export const sessionManagementEvaluator = withEvaluatorMeta(sessionManagementEvaluator_impl);
export const incidentResponseEvaluator = withEvaluatorMeta(incidentResponseEvaluator_impl);
export const threatIntelEvaluator = withEvaluatorMeta(threatIntelEvaluator_impl);
export const soarAutomationEvaluator = withEvaluatorMeta(soarAutomationEvaluator_impl);
export const passwordPolicyEvaluator = withEvaluatorMeta(passwordPolicyEvaluator_impl);
export const identityEvaluator = withEvaluatorMeta(identityEvaluator_impl);
export const deviceTrustEvaluator = withEvaluatorMeta(deviceTrustEvaluator_impl);
export const adaptiveAuthEvaluator = withEvaluatorMeta(adaptiveAuthEvaluator_impl);
export const digitalSignatureEvaluator = withEvaluatorMeta(digitalSignatureEvaluator_impl);
export const fileIntegrityEvaluator = withEvaluatorMeta(fileIntegrityEvaluator_impl);
export const cloudSecurityEvaluator = withEvaluatorMeta(cloudSecurityEvaluator_impl);
export const devSecOpsEvaluator = withEvaluatorMeta(devSecOpsEvaluator_impl);

export const EVALUATORS = {
  encryptionEvaluator,
  mfaEvaluator,
  threatDetectionEvaluator,
  malwareProtectionEvaluator,
  dlpEvaluator,
  zeroTrustEvaluator,
  auditLoggingEvaluator,
  sessionManagementEvaluator,
  incidentResponseEvaluator,
  threatIntelEvaluator,
  soarAutomationEvaluator,
  passwordPolicyEvaluator,
  identityEvaluator,
  deviceTrustEvaluator,
  adaptiveAuthEvaluator,
  digitalSignatureEvaluator,
  fileIntegrityEvaluator,
  cloudSecurityEvaluator,
  devSecOpsEvaluator
};
