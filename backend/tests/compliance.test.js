/**
 * Sanity tests for Phase 10 (Compliance & Governance), using Node's built-in test runner (same
 * convention as every prior phase's tests). controlEvaluators.js and policyEvaluator.js's
 * violation-checking are pure, DB-free functions tested directly, matching how
 * services/soar/ruleMatcher.js is tested in soarEngine.test.js/iam.test.js. The final section
 * chains evaluator output -> SIEM event shape -> ruleMatcher's new COMPLIANCE_SCORE_DROP mapping
 * together end-to-end (no DB), as an integration-style test.
 * Run with: node --test backend/tests
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
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
  devSecOpsEvaluator,
  platformOpsEvaluator,
  EVALUATORS
} from "../services/compliance/controlEvaluators.js";
import { evaluatePolicyViolations, validatePolicyValue, POLICY_DEFAULTS } from "../services/compliance/policyEvaluator.js";
import { computeRiskScore, riskDistribution, buildComplianceTrend } from "../services/compliance/riskScoring.js";
import { buildCsv, buildJson } from "../services/compliance/reportGenerator.js";
import { eventTriggerFor } from "../services/soar/ruleMatcher.js";

/* ------------------------------- controlEvaluators ------------------------------- */

test("encryptionEvaluator: PASS when every file is client-side encrypted", () => {
  const result = encryptionEvaluator({ encryption: { totalFiles: 10, encryptedFiles: 10 } });
  assert.equal(result.status, "PASS");
  assert.equal(result.score, 100);
});

test("encryptionEvaluator: FAIL when most files are unencrypted, with a recommendation", () => {
  const result = encryptionEvaluator({ encryption: { totalFiles: 10, encryptedFiles: 2 } });
  assert.equal(result.status, "FAIL");
  assert.ok(result.recommendations.length > 0);
});

test("encryptionEvaluator: NOT_APPLICABLE when there are no files yet", () => {
  const result = encryptionEvaluator({ encryption: { totalFiles: 0, encryptedFiles: 0 } });
  assert.equal(result.status, "NOT_APPLICABLE");
});

test("mfaEvaluator: PASS when MFA is required and fully adopted", () => {
  const result = mfaEvaluator({ mfa: { totalUsers: 5, mfaEnabledUsers: 5, requireMFA: true } });
  assert.equal(result.status, "PASS");
});

test("mfaEvaluator: FAIL when MFA is not required and adoption is low", () => {
  const result = mfaEvaluator({ mfa: { totalUsers: 10, mfaEnabledUsers: 1, requireMFA: false } });
  assert.equal(result.status, "FAIL");
  assert.ok(result.recommendations.some((r) => r.includes("Enable")));
});

test("threatDetectionEvaluator: PASS when all detected threats were quarantined", () => {
  const result = threatDetectionEvaluator({ threatDetection: { threatsDetected: 4, threatsQuarantined: 4 } });
  assert.equal(result.status, "PASS");
});

test("malwareProtectionEvaluator: FAIL when malware found is not blocked", () => {
  const result = malwareProtectionEvaluator({ malwareProtection: { scansRun: 20, malwareFound: 5, malwareBlocked: 0 } });
  assert.equal(result.status, "FAIL");
});

test("dlpEvaluator: FAIL when DLP enforcement is disabled regardless of history", () => {
  const result = dlpEvaluator({ dlp: { enforcement: false, violationsBlocked: 0, violationsTotal: 0 } });
  assert.equal(result.status, "FAIL");
  assert.ok(result.recommendations[0].includes("Enable DLP"));
});

test("zeroTrustEvaluator: caps score below PASS when untrusted devices aren't blocked", () => {
  const result = zeroTrustEvaluator({ zeroTrust: { policyChecksTotal: 10, policyChecksPassed: 10, blockUntrustedDevices: false } });
  assert.ok(result.score <= 80);
  assert.notEqual(result.status, "PASS");
});

test("auditLoggingEvaluator: FAIL when nothing was logged in 30 days", () => {
  const result = auditLoggingEvaluator({ auditLogging: { eventsLogged30d: 0 } });
  assert.equal(result.status, "FAIL");
});

test("sessionManagementEvaluator: PARTIAL when only one of timeout/max-sessions is configured", () => {
  const result = sessionManagementEvaluator({ sessionManagement: { sessionTimeoutMinutes: 30, maxSessions: 0 } });
  assert.equal(result.status, "PARTIAL");
});

test("incidentResponseEvaluator: PASS trivially when there are no incidents", () => {
  const result = incidentResponseEvaluator({ incidentResponse: { totalIncidents: 0, resolvedIncidents: 0 } });
  assert.equal(result.status, "PASS");
  assert.equal(result.score, 100);
});

test("incidentResponseEvaluator: FAIL when most incidents remain unresolved", () => {
  const result = incidentResponseEvaluator({ incidentResponse: { totalIncidents: 10, resolvedIncidents: 1 } });
  assert.equal(result.status, "FAIL");
});

test("threatIntelEvaluator: PARTIAL when no lookups were performed", () => {
  const result = threatIntelEvaluator({ threatIntel: { iocLookups30d: 0, iocMatches30d: 0 } });
  assert.equal(result.status, "PARTIAL");
});

test("soarAutomationEvaluator: FAIL when no automation rules are enabled", () => {
  const result = soarAutomationEvaluator({ soarAutomation: { enabledRules: 0, executions30d: 0, failedExecutions30d: 0 } });
  assert.equal(result.status, "FAIL");
});

test("cloudSecurityEvaluator (Phase 11): PASS with no open findings, FAIL on any open CRITICAL finding", () => {
  const clean = cloudSecurityEvaluator({ cloudSecurity: { openCritical: 0, openHigh: 0, totalOpen: 0 } });
  assert.equal(clean.status, "PASS");
  assert.equal(clean.score, 100);

  const critical = cloudSecurityEvaluator({ cloudSecurity: { openCritical: 1, openHigh: 2, totalOpen: 3 } });
  assert.equal(critical.status, "FAIL");
  assert.ok(critical.score < 100);
});

test("devSecOpsEvaluator (Phase 12): PASS with no open findings, FAIL on any open CRITICAL finding", () => {
  const clean = devSecOpsEvaluator({ devSecOps: { openCritical: 0, openHigh: 0, totalOpen: 0 } });
  assert.equal(clean.status, "PASS");
  assert.equal(clean.score, 100);

  const critical = devSecOpsEvaluator({ devSecOps: { openCritical: 1, openHigh: 2, totalOpen: 3 } });
  assert.equal(critical.status, "FAIL");
  assert.ok(critical.score < 100);
});

test("platformOpsEvaluator (Phase 13): PASS with full availability/health/recent backup, degrades otherwise", () => {
  const healthy = platformOpsEvaluator({ platformOps: { availabilityPct: 100, healthScore: 100, hoursSinceLastBackup: 2 } });
  assert.equal(healthy.status, "PASS");

  const degraded = platformOpsEvaluator({ platformOps: { availabilityPct: 50, healthScore: 40, hoursSinceLastBackup: null } });
  assert.notEqual(degraded.status, "PASS");
  assert.ok(degraded.score < healthy.score);
});

test("EVALUATORS registry exposes exactly the 20 documented evaluator keys", () => {
  const expectedKeys = [
    "encryptionEvaluator", "mfaEvaluator", "threatDetectionEvaluator", "malwareProtectionEvaluator",
    "dlpEvaluator", "zeroTrustEvaluator", "auditLoggingEvaluator", "sessionManagementEvaluator",
    "incidentResponseEvaluator", "threatIntelEvaluator", "soarAutomationEvaluator",
    "passwordPolicyEvaluator", "identityEvaluator", "deviceTrustEvaluator", "adaptiveAuthEvaluator",
    "digitalSignatureEvaluator", "fileIntegrityEvaluator",
    // Phase 11 (CSPM/ASM)
    "cloudSecurityEvaluator",
    // Phase 12 (DevSecOps/Supply Chain)
    "devSecOpsEvaluator",
    // Phase 13 (Platform Operations)
    "platformOpsEvaluator"
  ];
  assert.deepEqual(Object.keys(EVALUATORS).sort(), expectedKeys.sort());
});

test("every evaluator's result carries a derived severity and evidence array", () => {
  const result = encryptionEvaluator({ encryption: { totalFiles: 10, encryptedFiles: 2 } });
  assert.equal(result.status, "FAIL");
  assert.equal(result.severity, "HIGH");
  assert.ok(Array.isArray(result.evidence));
  assert.ok(result.evidence.length > 0);
});

test("passwordPolicyEvaluator: FAIL on weak defaults, PASS on strong policy", () => {
  const weak = passwordPolicyEvaluator({ passwordPolicy: { minPasswordLength: 6, requirePasswordComplexity: false, passwordExpiryDays: 0 } });
  assert.equal(weak.status, "FAIL");
  const strong = passwordPolicyEvaluator({ passwordPolicy: { minPasswordLength: 12, requirePasswordComplexity: true, passwordExpiryDays: 90 } });
  assert.equal(strong.status, "PASS");
});

test("identityEvaluator: NOT_APPLICABLE with no users, FAIL with poor role coverage", () => {
  assert.equal(identityEvaluator({ identity: { totalUsers: 0 } }).status, "NOT_APPLICABLE");
  const result = identityEvaluator({ identity: { totalUsers: 10, roleAssignedUsers: 2, privilegedUsers: 1, inactiveUsers90d: 0 } });
  assert.equal(result.status, "FAIL");
});

test("deviceTrustEvaluator: PASS when nearly all devices are trusted", () => {
  const result = deviceTrustEvaluator({ deviceTrust: { totalDevices: 10, trustedDevices: 10, revokedDevices: 0 } });
  assert.equal(result.status, "PASS");
});

test("adaptiveAuthEvaluator: PASS trivially with no risk events, FAIL when high-risk logins go unchallenged", () => {
  assert.equal(adaptiveAuthEvaluator({ adaptiveAuth: { riskEventsTotal: 0, highRiskChallenged: 0 } }).status, "PASS");
  const result = adaptiveAuthEvaluator({ adaptiveAuth: { riskEventsTotal: 10, highRiskChallenged: 1 } });
  assert.equal(result.status, "FAIL");
});

test("digitalSignatureEvaluator: NOT_APPLICABLE with no files, FAIL when files are unsigned", () => {
  assert.equal(digitalSignatureEvaluator({ digitalSignature: { totalFiles: 0, signedFiles: 0 } }).status, "NOT_APPLICABLE");
  const result = digitalSignatureEvaluator({ digitalSignature: { totalFiles: 10, signedFiles: 1 } });
  assert.equal(result.status, "FAIL");
});

test("fileIntegrityEvaluator: PASS when all files carry an integrity hash", () => {
  const result = fileIntegrityEvaluator({ fileIntegrity: { totalFiles: 10, hashedFiles: 10 } });
  assert.equal(result.status, "PASS");
});

/* ------------------------------- policyEvaluator ------------------------------- */

test("evaluatePolicyViolations: flags an oversized upload against MAX_UPLOAD_SIZE_MB", () => {
  const violations = evaluatePolicyViolations(POLICY_DEFAULTS, { uploadSizeMB: 500 });
  assert.equal(violations.length, 1);
  assert.match(violations[0], /exceeds MAX_UPLOAD_SIZE_MB/);
});

test("evaluatePolicyViolations: flags a blocked file extension", () => {
  const policyValues = { ...POLICY_DEFAULTS, BLOCKED_FILE_TYPES: ["exe", "bat"] };
  const violations = evaluatePolicyViolations(policyValues, { fileExtension: "EXE" });
  assert.equal(violations.length, 1);
});

test("evaluatePolicyViolations: flags a restricted country", () => {
  const policyValues = { ...POLICY_DEFAULTS, RESTRICTED_COUNTRIES: ["KP"] };
  const violations = evaluatePolicyViolations(policyValues, { country: "KP" });
  assert.equal(violations.length, 1);
});

test("evaluatePolicyViolations: returns no violations for compliant state", () => {
  const violations = evaluatePolicyViolations(POLICY_DEFAULTS, { uploadSizeMB: 5, fileExtension: "pdf", country: "US", dlpDecision: "allow" });
  assert.deepEqual(violations, []);
});

test("validatePolicyValue: rejects wrong types per policy name, accepts valid ones", () => {
  assert.equal(validatePolicyValue("MAX_UPLOAD_SIZE_MB", -5), "MAX_UPLOAD_SIZE_MB must be a positive number");
  assert.equal(validatePolicyValue("MAX_UPLOAD_SIZE_MB", 250), null);
  assert.equal(validatePolicyValue("BLOCKED_FILE_TYPES", "exe"), "BLOCKED_FILE_TYPES must be an array of strings");
  assert.equal(validatePolicyValue("BLOCKED_FILE_TYPES", ["exe", "bat"]), null);
  assert.equal(validatePolicyValue("DLP_ENFORCEMENT", "yes"), "DLP_ENFORCEMENT must be a boolean");
  assert.equal(validatePolicyValue("DLP_ENFORCEMENT", true), null);
  assert.match(validatePolicyValue("NOT_A_REAL_POLICY", 1), /Unknown policy name/);
});

/* ------------------------------- reportGenerator ------------------------------- */

const SAMPLE_REPORT_DATA = {
  overallScore: 82,
  riskScore: 18,
  riskDistribution: { Low: 1, Medium: 2, High: 1, Critical: 0 },
  frameworkScores: [{ framework: "ISO27001", name: "ISO/IEC 27001:2022", score: 82, controlCount: 8 }],
  assessments: [
    { frameworkKey: "ISO27001", controlId: "A.8.24", title: "Use of Cryptography", category: "Cryptography", severity: "CRITICAL", status: "PASS", score: 100, recommendations: [], evaluatedAt: "2026-07-01T00:00:00Z" }
  ],
  trend: [{ day: "2026-07-01", averageScore: 82 }],
  generatedAt: "2026-07-04T00:00:00Z"
};

test("buildCsv: includes a risk-score summary line and a full data row per assessment", () => {
  const csv = buildCsv(SAMPLE_REPORT_DATA);
  assert.match(csv, /Overall Risk Score: 18\/100/);
  assert.match(csv, /A\.8\.24/);
  assert.match(csv, /Use of Cryptography/);
});

test("buildJson: returns overallScore, riskScore, riskDistribution, frameworkScores, assessments, and trend", () => {
  const json = buildJson(SAMPLE_REPORT_DATA);
  assert.deepEqual(Object.keys(json).sort(), ["assessments", "frameworkScores", "generatedAt", "overallScore", "riskDistribution", "riskScore", "trend"].sort());
  assert.equal(json.overallScore, 82);
  assert.equal(json.riskScore, 18);
});

/* ------------------------------- riskScoring ------------------------------- */

test("computeRiskScore: zero for an all-passing assessment set", () => {
  const score = computeRiskScore([
    { status: "PASS", severity: "CRITICAL" },
    { status: "PASS", severity: "HIGH" }
  ]);
  assert.equal(score, 0);
});

test("computeRiskScore: a failed CRITICAL control weighs far more than a failed LOW one", () => {
  const criticalFail = computeRiskScore([{ status: "FAIL", severity: "CRITICAL" }]);
  const lowFail = computeRiskScore([{ status: "FAIL", severity: "LOW" }]);
  assert.ok(criticalFail > lowFail);
});

test("computeRiskScore: PARTIAL counts as half the weight of FAIL", () => {
  const failScore = computeRiskScore([{ status: "FAIL", severity: "HIGH" }]);
  const partialScore = computeRiskScore([{ status: "PARTIAL", severity: "HIGH" }]);
  assert.equal(partialScore, Math.round(failScore / 2));
});

test("computeRiskScore: empty input returns 0, not NaN/throw", () => {
  assert.equal(computeRiskScore([]), 0);
  assert.equal(computeRiskScore(undefined), 0);
});

test("riskDistribution: buckets non-passing assessments by severity, ignores PASS/NOT_APPLICABLE", () => {
  const result = riskDistribution([
    { status: "FAIL", severity: "CRITICAL" },
    { status: "FAIL", severity: "HIGH" },
    { status: "PARTIAL", severity: "MEDIUM" },
    { status: "PASS", severity: "CRITICAL" },
    { status: "NOT_APPLICABLE", severity: "HIGH" }
  ]);
  assert.deepEqual(result, { Low: 0, Medium: 1, High: 1, Critical: 1 });
});

test("buildComplianceTrend: groups scores by day and averages them", () => {
  const trend = buildComplianceTrend([
    { score: 80, evaluatedAt: "2026-07-01T10:00:00Z" },
    { score: 90, evaluatedAt: "2026-07-01T14:00:00Z" },
    { score: 60, evaluatedAt: "2026-07-02T09:00:00Z" }
  ]);
  assert.deepEqual(trend, [
    { day: "2026-07-01", averageScore: 85 },
    { day: "2026-07-02", averageScore: 60 }
  ]);
});

/* ------------------------------- ruleMatcher integration ------------------------------- */

test("eventTriggerFor: compliance_scan with scoreDropped metadata maps to COMPLIANCE_SCORE_DROP", () => {
  assert.equal(eventTriggerFor({ type: "compliance_scan", metadata: { scoreDropped: true } }), "COMPLIANCE_SCORE_DROP");
  assert.equal(eventTriggerFor({ type: "compliance_scan", metadata: { scoreDropped: false } }), null);
});

test("eventTriggerFor: control_failed only triggers COMPLIANCE_SCORE_DROP for CRITICAL severity", () => {
  assert.equal(eventTriggerFor({ type: "control_failed", metadata: { severity: "CRITICAL" } }), "COMPLIANCE_SCORE_DROP");
  assert.equal(eventTriggerFor({ type: "control_failed", metadata: { severity: "MEDIUM" } }), null);
});

test("integration: a failing critical control's evaluator result flows into a triggering compliance_scan event", () => {
  const evaluatorResult = encryptionEvaluator({ encryption: { totalFiles: 10, encryptedFiles: 0 } });
  assert.equal(evaluatorResult.status, "FAIL");

  const overallScore = evaluatorResult.score; // simulate a single-control run for simplicity
  const scanEvent = { type: "compliance_scan", metadata: { scoreDropped: overallScore < 70 } };
  assert.equal(eventTriggerFor(scanEvent), "COMPLIANCE_SCORE_DROP");
});
