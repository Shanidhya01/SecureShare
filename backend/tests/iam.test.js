/**
 * Sanity tests for Phase 9 (IAM/MFA) and Phase 9.5 (Adaptive Authentication), using Node's
 * built-in test runner (same convention as every prior phase's tests). TOTP/recovery-code tests
 * exercise real crypto (otplib/bcrypt) but no DB; loginRiskEngine/policyEngine are pure; the
 * ruleMatcher tests extend Phase 8's existing soarEngine.test.js coverage with the
 * login_failed -> MULTIPLE_FAILED_LOGINS, impossible_travel -> IMPOSSIBLE_TRAVEL, and
 * step_up_auth -> CRITICAL_RISK_LOGIN mappings. The final section chains riskEngine -> event
 * shape -> ruleMatcher together end-to-end (no DB) as an integration-style test.
 * Run with: node --test backend/tests
 */
import test from "node:test";
import assert from "node:assert/strict";
import { generateSecret, generateToken, verifyToken, buildOtpauthUri } from "../services/iam/totp.js";
import { generateRecoveryCodes, consumeRecoveryCode } from "../services/iam/recoveryCodes.js";
import { scoreLogin, detectImpossibleTravel } from "../services/iam/loginRiskEngine.js";
import {
  evaluateCountryPolicy,
  evaluateSessionLimit,
  evaluatePasswordExpiry,
  evaluateMfaRequirement,
  evaluateDevicePolicy,
  evaluatePasswordPolicy,
  evaluateSessionTimeout
} from "../services/iam/policyEngine.js";
import { eventTriggerFor, matchRules } from "../services/soar/ruleMatcher.js";
import { runPlaybook } from "../services/soar/playbookRunner.js";

/* ------------------------------- TOTP ------------------------------- */

test("TOTP: generateSecret produces a usable base32 secret, and a generated token verifies", async () => {
  const secret = generateSecret();
  assert.equal(typeof secret, "string");
  assert.ok(secret.length > 0);

  const token = await generateToken(secret);
  assert.match(token, /^\d{6}$/);

  const ok = await verifyToken(token, secret);
  assert.equal(ok, true);
});

test("TOTP: verifyToken rejects a wrong code", async () => {
  const secret = generateSecret();
  const ok = await verifyToken("000000", secret);
  assert.equal(ok, false);
});

test("TOTP: verifyToken fails closed (false, not throw) on missing input", async () => {
  assert.equal(await verifyToken(null, "SOMESECRET"), false);
  assert.equal(await verifyToken("123456", null), false);
});

test("TOTP: buildOtpauthUri embeds the account and issuer", () => {
  const secret = generateSecret();
  const uri = buildOtpauthUri(secret, "user@example.com", "SecureShare");
  assert.match(uri, /^otpauth:\/\/totp\//);
  assert.match(uri, /SecureShare/);
  assert.match(uri, /user%40example\.com/);
});

/* ------------------------------- Recovery codes ------------------------------- */

test("recovery codes: generates the requested count, and each one verifies+consumes correctly", async () => {
  const { plaintextCodes, hashes } = await generateRecoveryCodes(5);
  assert.equal(plaintextCodes.length, 5);
  assert.equal(hashes.length, 5);

  const remaining = await consumeRecoveryCode(plaintextCodes[2], hashes);
  assert.ok(remaining);
  assert.equal(remaining.length, 4);
});

test("recovery codes: a used code cannot be consumed twice", async () => {
  const { plaintextCodes, hashes } = await generateRecoveryCodes(3);
  const afterFirst = await consumeRecoveryCode(plaintextCodes[0], hashes);
  assert.ok(afterFirst);

  const afterSecondAttempt = await consumeRecoveryCode(plaintextCodes[0], afterFirst);
  assert.equal(afterSecondAttempt, null);
});

test("recovery codes: an unknown code returns null without consuming anything", async () => {
  const { hashes } = await generateRecoveryCodes(3);
  const result = await consumeRecoveryCode("ZZZZZ-ZZZZZ", hashes);
  assert.equal(result, null);
});

/* ------------------------------- loginRiskEngine ------------------------------- */

test("scoreLogin: no signals scores Low with no reasons", () => {
  const result = scoreLogin({});
  assert.equal(result.level, "Low");
  assert.equal(result.score, 0);
  assert.deepEqual(result.reasons, []);
});

test("scoreLogin: an IOC-matched IP alone reaches Medium", () => {
  const result = scoreLogin({ ipIocMatch: true });
  assert.equal(result.score, 40);
  assert.equal(result.level, "Medium");
});

test("scoreLogin: a Tor exit node alone reaches Medium", () => {
  const result = scoreLogin({ isTor: true });
  assert.equal(result.score, 35);
  assert.equal(result.level, "Medium");
});

test("scoreLogin: impossible travel alone reaches Medium", () => {
  const result = scoreLogin({ impossibleTravel: true });
  assert.equal(result.score, 40);
  assert.equal(result.level, "Medium");
});

test("scoreLogin: new device + country change compounds to Medium", () => {
  const result = scoreLogin({ isNewDevice: true, countryChanged: true });
  assert.equal(result.score, 35);
  assert.equal(result.level, "Medium");
  assert.equal(result.reasons.length, 2);
});

test("scoreLogin: IOC match + Tor reaches High", () => {
  const result = scoreLogin({ ipIocMatch: true, isTor: true });
  assert.equal(result.score, 75);
  assert.equal(result.level, "High");
});

test("scoreLogin: IOC match + impossible travel reaches Critical", () => {
  const result = scoreLogin({ ipIocMatch: true, impossibleTravel: true });
  assert.equal(result.score, 80);
  assert.equal(result.level, "Critical");
});

test("scoreLogin: score is capped at 100 even when every signal fires", () => {
  const result = scoreLogin({
    isNewDevice: true,
    ipIocMatch: true,
    countryChanged: true,
    isVpn: true,
    isTor: true,
    impossibleTravel: true
  });
  assert.equal(result.score, 100);
  assert.equal(result.level, "Critical");
  assert.equal(result.reasons.length, 6);
});

/* ------------------------------- detectImpossibleTravel ------------------------------- */

test("detectImpossibleTravel: false when there is no prior session", () => {
  assert.equal(detectImpossibleTravel(null, "US"), false);
});

test("detectImpossibleTravel: false when the country didn't change", () => {
  const lastSession = { country: "US", createdAt: new Date(Date.now() - 5 * 60000) };
  assert.equal(detectImpossibleTravel(lastSession, "US"), false);
});

test("detectImpossibleTravel: true when the country changed within the window", () => {
  const lastSession = { country: "US", createdAt: new Date(Date.now() - 10 * 60000) };
  assert.equal(detectImpossibleTravel(lastSession, "JP"), true);
});

test("detectImpossibleTravel: false when the country changed but plenty of time passed", () => {
  const lastSession = { country: "US", createdAt: new Date(Date.now() - 24 * 60 * 60000) };
  assert.equal(detectImpossibleTravel(lastSession, "JP"), false);
});

/* ------------------------------- policyEngine ------------------------------- */

test("evaluateCountryPolicy: allows everything when allowedCountries is empty", () => {
  assert.equal(evaluateCountryPolicy({ allowedCountries: [] }, "US").allowed, true);
});

test("evaluateCountryPolicy: denies a country not in the allow-list", () => {
  const result = evaluateCountryPolicy({ allowedCountries: ["US", "CA"] }, "RU");
  assert.equal(result.allowed, false);
  assert.match(result.reason, /RU/);
});

test("evaluateCountryPolicy: fails open when country could not be resolved", () => {
  assert.equal(evaluateCountryPolicy({ allowedCountries: ["US"] }, null).allowed, true);
});

test("evaluateSessionLimit: disabled (0) never flags for revocation", () => {
  assert.equal(evaluateSessionLimit({ maxSessions: 0 }, 999).shouldRevokeOldest, false);
});

test("evaluateSessionLimit: flags once the active count meets the max", () => {
  assert.equal(evaluateSessionLimit({ maxSessions: 3 }, 3).shouldRevokeOldest, true);
  assert.equal(evaluateSessionLimit({ maxSessions: 3 }, 2).shouldRevokeOldest, false);
});

test("evaluatePasswordExpiry: not expired when disabled or recent", () => {
  assert.equal(evaluatePasswordExpiry({ passwordExpiryDays: 0 }, { passwordChangedAt: new Date(0) }).expired, false);
  assert.equal(evaluatePasswordExpiry({ passwordExpiryDays: 90 }, { passwordChangedAt: new Date() }).expired, false);
});

test("evaluatePasswordExpiry: expired once older than the configured window", () => {
  const oldDate = new Date(Date.now() - 100 * 24 * 60 * 60 * 1000);
  assert.equal(evaluatePasswordExpiry({ passwordExpiryDays: 90 }, { passwordChangedAt: oldDate }).expired, true);
});

test("evaluateMfaRequirement: not required when policy doesn't require it", () => {
  assert.equal(evaluateMfaRequirement({ requireMFA: false }, { mfa: { enabled: false } }).required, false);
});

test("evaluateMfaRequirement: required when policy demands it and user has neither MFA nor a passkey", () => {
  assert.equal(evaluateMfaRequirement({ requireMFA: true }, { mfa: { enabled: false } }, false).required, true);
});

test("evaluateMfaRequirement: satisfied by either TOTP MFA or a passkey", () => {
  assert.equal(evaluateMfaRequirement({ requireMFA: true }, { mfa: { enabled: true } }, false).required, false);
  assert.equal(evaluateMfaRequirement({ requireMFA: true }, { mfa: { enabled: false } }, true).required, false);
});

test("evaluateDevicePolicy: allows any device when no restriction is configured", () => {
  assert.equal(evaluateDevicePolicy({}, "device-1", false).allowed, true);
});

test("evaluateDevicePolicy: blockUntrustedDevices denies a new/unrecognized device", () => {
  const result = evaluateDevicePolicy({ blockUntrustedDevices: true }, "device-1", true);
  assert.equal(result.allowed, false);
});

test("evaluateDevicePolicy: blockUntrustedDevices allows an already-known device", () => {
  assert.equal(evaluateDevicePolicy({ blockUntrustedDevices: true }, "device-1", false).allowed, true);
});

test("evaluateDevicePolicy: allowedDeviceIds acts as an explicit allow-list", () => {
  const policy = { allowedDeviceIds: ["device-1", "device-2"] };
  assert.equal(evaluateDevicePolicy(policy, "device-1", false).allowed, true);
  assert.equal(evaluateDevicePolicy(policy, "device-99", false).allowed, false);
});

test("evaluatePasswordPolicy: rejects a password shorter than the minimum length", () => {
  const result = evaluatePasswordPolicy({ minPasswordLength: 10 }, "short1");
  assert.equal(result.valid, false);
  assert.match(result.reason, /10/);
});

test("evaluatePasswordPolicy: complexity requires upper/lower/digit/symbol", () => {
  const policy = { minPasswordLength: 6, requirePasswordComplexity: true };
  assert.equal(evaluatePasswordPolicy(policy, "alllowercase1").valid, false);
  assert.equal(evaluatePasswordPolicy(policy, "Aa1!aaaa").valid, true);
});

test("evaluateSessionTimeout: disabled (0) never expires", () => {
  assert.equal(evaluateSessionTimeout({ sessionTimeoutMinutes: 0 }, new Date(0)).expired, false);
});

test("evaluateSessionTimeout: expires once idle longer than the configured window", () => {
  const staleActivity = new Date(Date.now() - 61 * 60000);
  assert.equal(evaluateSessionTimeout({ sessionTimeoutMinutes: 60 }, staleActivity).expired, true);
  const recentActivity = new Date(Date.now() - 5 * 60000);
  assert.equal(evaluateSessionTimeout({ sessionTimeoutMinutes: 60 }, recentActivity).expired, false);
});

/* ------------------------------- SOAR integration: login_failed trigger ------------------------------- */

test("eventTriggerFor: login_failed only maps to MULTIPLE_FAILED_LOGINS at 3+ recent failures", () => {
  assert.equal(eventTriggerFor({ type: "login_failed", metadata: { recentFailureCount: 1 } }), null);
  assert.equal(eventTriggerFor({ type: "login_failed", metadata: { recentFailureCount: 2 } }), null);
  assert.equal(eventTriggerFor({ type: "login_failed", metadata: { recentFailureCount: 3 } }), "MULTIPLE_FAILED_LOGINS");
  assert.equal(eventTriggerFor({ type: "login_failed", metadata: { recentFailureCount: 10 } }), "MULTIPLE_FAILED_LOGINS");
});

test("eventTriggerFor: login_failed with no metadata does not throw and does not match", () => {
  assert.equal(eventTriggerFor({ type: "login_failed" }), null);
});

test("matchRules: an Account Lockdown rule fires once the failure threshold is met", () => {
  const rule = { name: "lockdown", enabled: true, trigger: "MULTIPLE_FAILED_LOGINS", conditions: [], priority: 10 };
  const belowThreshold = matchRules({ type: "login_failed", metadata: { recentFailureCount: 2 } }, [rule]);
  const atThreshold = matchRules({ type: "login_failed", metadata: { recentFailureCount: 3 } }, [rule]);
  assert.deepEqual(belowThreshold, []);
  assert.equal(atThreshold.length, 1);
});

/* ------------------------------- SOAR integration: Phase 9.5 adaptive-auth triggers ------------------------------- */

test("eventTriggerFor: impossible_travel unconditionally maps to IMPOSSIBLE_TRAVEL", () => {
  assert.equal(eventTriggerFor({ type: "impossible_travel", metadata: {} }), "IMPOSSIBLE_TRAVEL");
});

test("eventTriggerFor: step_up_auth only maps to CRITICAL_RISK_LOGIN at Critical risk level", () => {
  assert.equal(eventTriggerFor({ type: "step_up_auth", metadata: { riskLevel: "High" } }), null);
  assert.equal(eventTriggerFor({ type: "step_up_auth", metadata: { riskLevel: "Critical" } }), "CRITICAL_RISK_LOGIN");
});

test("matchRules: Critical Risk Response fires for both impossible travel and critical-risk step-up events", () => {
  const rule = { name: "critical-risk", enabled: true, trigger: "IMPOSSIBLE_TRAVEL", conditions: [], priority: 5 };
  const otherRule = { name: "critical-risk-2", enabled: true, trigger: "CRITICAL_RISK_LOGIN", conditions: [], priority: 5 };

  const travelMatch = matchRules({ type: "impossible_travel", metadata: {} }, [rule, otherRule]);
  const criticalLoginMatch = matchRules({ type: "step_up_auth", metadata: { riskLevel: "Critical" } }, [rule, otherRule]);
  const nonCriticalLoginMatch = matchRules({ type: "step_up_auth", metadata: { riskLevel: "Medium" } }, [rule, otherRule]);

  assert.equal(travelMatch.length, 1);
  assert.equal(travelMatch[0].name, "critical-risk");
  assert.equal(criticalLoginMatch.length, 1);
  assert.equal(criticalLoginMatch[0].name, "critical-risk-2");
  assert.deepEqual(nonCriticalLoginMatch, []);
});

/* ------------------------------- Integration: risk engine -> event -> SOAR trigger -> playbook ------------------------------- */

test("integration: a Critical-risk login (impossible travel) end-to-end triggers and runs the Critical Risk Response playbook", async () => {
  // 1. Score the login exactly as auth.controller.js would.
  const lastSession = { country: "US", createdAt: new Date(Date.now() - 15 * 60000) };
  const currentCountry = "RU";
  const impossibleTravel = detectImpossibleTravel(lastSession, currentCountry);
  assert.equal(impossibleTravel, true);

  const risk = scoreLogin({ isNewDevice: true, ipIocMatch: true, impossibleTravel });
  assert.equal(risk.level, "Critical");

  // 2. Shape the two events auth.controller.js would emit for this login.
  const impossibleTravelEvent = { type: "impossible_travel", owner: "user-1", metadata: { previousCountry: lastSession.country } };
  const stepUpEvent = { type: "step_up_auth", owner: "user-1", metadata: { riskLevel: risk.level, riskScore: risk.score } };

  // 3. Both should route to the seeded Critical Risk Response playbook's rules.
  const rules = [
    { name: "Auto-respond to impossible travel", enabled: true, trigger: "IMPOSSIBLE_TRAVEL", conditions: [], priority: 5 },
    { name: "Auto-respond to critical-risk logins", enabled: true, trigger: "CRITICAL_RISK_LOGIN", conditions: [], priority: 5 }
  ];
  assert.equal(matchRules(impossibleTravelEvent, rules)[0].name, "Auto-respond to impossible travel");
  assert.equal(matchRules(stepUpEvent, rules)[0].name, "Auto-respond to critical-risk logins");

  // 4. Run the actual playbook steps (stubbed handlers) to confirm the full chain executes.
  const executed = [];
  const handlers = {
    requireMfaStepUp: async () => { executed.push("requireMfaStepUp"); return { success: true, detail: "flagged" }; },
    raiseIncident: async () => { executed.push("raiseIncident"); return { success: true, detail: "raised" }; },
    notifyUser: async () => { executed.push("notifyUser"); return { success: true, detail: "notified" }; }
  };
  const { status } = await runPlaybook(
    { steps: [{ type: "requireMfaStepUp" }, { type: "raiseIncident" }, { type: "notifyUser" }] },
    stepUpEvent,
    {},
    handlers
  );
  assert.equal(status, "completed");
  assert.deepEqual(executed, ["requireMfaStepUp", "raiseIncident", "notifyUser"]);
});
