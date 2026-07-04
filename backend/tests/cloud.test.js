/**
 * Phase 11 (CSPM/ASM) tests, using Node's built-in test runner (same convention as
 * backend/tests/soarEngine.test.js and backend/tests/compliance.test.js). Every pure function is
 * tested directly without a live MongoDB connection; DB-touching entry points are exercised only
 * for guard/early-return behavior that doesn't require Mongo.
 * Run with: node --test backend/tests
 */
import test from "node:test";
import assert from "node:assert/strict";
import { CONFIG_SCAN_RULES } from "../services/cloud/configScanner.js";
import { daysRemaining, tierForDaysRemaining, resolveMonitoredDomains } from "../services/cloud/certificateMonitor.js";
import { computeOverallScore } from "../services/cloud/scoreEngine.js";
import { resolveBaseUrl } from "../services/cloud/attackSurfaceScanner.js";
import { eventTriggerFor, matchRules } from "../services/soar/ruleMatcher.js";
import { resolveEventMeta } from "../services/siem/eventCatalog.js";

/* ------------------------------- configScanner rules ------------------------------- */

test("configScanner rules are all uniquely identified pure functions", () => {
  const ids = CONFIG_SCAN_RULES.map((r) => r.ruleId);
  assert.equal(new Set(ids).size, ids.length);
  for (const rule of CONFIG_SCAN_RULES) {
    assert.equal(typeof rule.check, "function");
    assert.ok(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(rule.severity));
  }
});

test("missing-helmet rule fires when helmet isn't a dependency", () => {
  const rule = CONFIG_SCAN_RULES.find((r) => r.ruleId === "missing-helmet");
  assert.equal(rule.check({ hasHelmet: false }), true);
  assert.equal(rule.check({ hasHelmet: true }), false);
});

test("weak-cors rule fires only when cors() is called with no options", () => {
  const rule = CONFIG_SCAN_RULES.find((r) => r.ruleId === "weak-cors");
  assert.equal(rule.check({ corsWideOpen: true }), true);
  assert.equal(rule.check({ corsWideOpen: false }), false);
});

test("weak-jwt-configuration rule only fires for a short, non-empty secret", () => {
  const rule = CONFIG_SCAN_RULES.find((r) => r.ruleId === "weak-jwt-configuration");
  assert.equal(rule.check({ jwtSecretLength: 10 }), true);
  assert.equal(rule.check({ jwtSecretLength: 64 }), false);
  assert.equal(rule.check({ jwtSecretLength: 0 }), false); // unset - not this scanner's concern
});

test("open-admin-apis rule fires only when an admin route file is missing requireAdmin", () => {
  const rule = CONFIG_SCAN_RULES.find((r) => r.ruleId === "open-admin-apis");
  assert.equal(rule.check({ adminGatingMissing: [] }), false);
  assert.equal(rule.check({ adminGatingMissing: ["soar.routes.js"] }), true);
});

test("cookie-flags-not-applicable and weak-cookie-settings are mutually exclusive", () => {
  const notApplicable = CONFIG_SCAN_RULES.find((r) => r.ruleId === "cookie-flags-not-applicable");
  const weak = CONFIG_SCAN_RULES.find((r) => r.ruleId === "weak-cookie-settings");
  assert.equal(notApplicable.check({ usesCookies: false }), true);
  assert.equal(weak.check({ usesCookies: false }), false);
  assert.equal(notApplicable.check({ usesCookies: true }), false);
  assert.equal(weak.check({ usesCookies: true }), true);
});

/* ------------------------------- certificateMonitor ------------------------------- */

test("daysRemaining computes whole days between now and expiry", () => {
  const now = new Date("2026-01-01T00:00:00Z");
  assert.equal(daysRemaining(new Date("2026-01-31T00:00:00Z"), now), 30);
  assert.equal(daysRemaining(new Date("2025-12-31T00:00:00Z"), now), -1);
});

test("tierForDaysRemaining buckets into the 30/15/7/expired thresholds", () => {
  assert.equal(tierForDaysRemaining(45), "none");
  assert.equal(tierForDaysRemaining(30), "30");
  assert.equal(tierForDaysRemaining(20), "30");
  assert.equal(tierForDaysRemaining(15), "15");
  assert.equal(tierForDaysRemaining(10), "15");
  assert.equal(tierForDaysRemaining(7), "7");
  assert.equal(tierForDaysRemaining(1), "7");
  assert.equal(tierForDaysRemaining(0), "expired");
  assert.equal(tierForDaysRemaining(-5), "expired");
});

test("resolveMonitoredDomains dedupes CLOUD_MONITORED_DOMAINS and skips non-HTTPS origins", () => {
  const original = { domains: process.env.CLOUD_MONITORED_DOMAINS, origin: process.env.WEBAUTHN_ORIGIN };
  process.env.CLOUD_MONITORED_DOMAINS = "example.com, example.com , api.example.com";
  process.env.WEBAUTHN_ORIGIN = "http://localhost:3000";
  assert.deepEqual(resolveMonitoredDomains().sort(), ["api.example.com", "example.com"]);

  process.env.WEBAUTHN_ORIGIN = "https://app.example.com";
  assert.ok(resolveMonitoredDomains().includes("app.example.com"));

  process.env.CLOUD_MONITORED_DOMAINS = original.domains;
  process.env.WEBAUTHN_ORIGIN = original.origin;
});

/* ------------------------------- scoreEngine ------------------------------- */

test("computeOverallScore returns 100 when every component score is 100", () => {
  const perfect = { assetScore: 100, configScore: 100, exposureScore: 100, certScore: 100, identityScore: 100, complianceScore: 100 };
  assert.equal(computeOverallScore(perfect), 100);
});

test("computeOverallScore weights configScore/exposureScore more heavily than identity/compliance", () => {
  const weakConfig = { assetScore: 100, configScore: 0, exposureScore: 100, certScore: 100, identityScore: 100, complianceScore: 100 };
  const weakIdentity = { assetScore: 100, configScore: 100, exposureScore: 100, certScore: 100, identityScore: 0, complianceScore: 100 };
  assert.ok(computeOverallScore(weakConfig) < computeOverallScore(weakIdentity));
});

test("computeOverallScore clamps to [0, 100]", () => {
  const allZero = { assetScore: 0, configScore: 0, exposureScore: 0, certScore: 0, identityScore: 0, complianceScore: 0 };
  assert.equal(computeOverallScore(allZero), 0);
});

/* ------------------------------- attackSurfaceScanner ------------------------------- */

test("resolveBaseUrl defaults to localhost with the configured PORT", () => {
  const original = { base: process.env.APP_BASE_URL, port: process.env.PORT };
  delete process.env.APP_BASE_URL;
  process.env.PORT = "6001";
  assert.equal(resolveBaseUrl(), "http://localhost:6001");
  process.env.APP_BASE_URL = original.base;
  process.env.PORT = original.port;
});

/* ------------------------------- SOAR integration (Phase 11 triggers) ------------------------------- */

test("eventTriggerFor maps new Phase 11 event types to their triggers", () => {
  assert.equal(eventTriggerFor({ type: "public_exposure", metadata: { severity: "CRITICAL" } }), "PUBLIC_EXPOSURE_CRITICAL");
  assert.equal(eventTriggerFor({ type: "public_exposure", metadata: { severity: "MEDIUM" } }), null);
  assert.equal(eventTriggerFor({ type: "certificate_expired" }), "CERTIFICATE_EXPIRED");
  assert.equal(eventTriggerFor({ type: "cloud_ioc_match" }), "IOC_MATCH");
  assert.equal(eventTriggerFor({ type: "security_score_updated", metadata: { scoreDropped: true } }), "CLOUD_SCORE_DROP");
  assert.equal(eventTriggerFor({ type: "security_score_updated", metadata: { scoreDropped: false } }), null);
});

test("matchRules matches Phase 11 rules by their new trigger values", () => {
  const rules = [{ enabled: true, trigger: "CERTIFICATE_EXPIRED", conditions: [], priority: 10, name: "cert" }];
  const matched = matchRules({ type: "certificate_expired" }, rules);
  assert.equal(matched.length, 1);
  assert.equal(matched[0].name, "cert");
});

/* ------------------------------- SIEM integration (Phase 11 event catalog) ------------------------------- */

test("every Phase 11 SIEM event type resolves to the CLOUD category", () => {
  const types = [
    "asset_discovered", "asset_updated", "configuration_scan", "configuration_failure",
    "public_exposure", "weak_tls", "certificate_expiring", "certificate_expired",
    "missing_security_headers", "cloud_risk_updated", "security_score_updated", "cloud_ioc_match"
  ];
  for (const type of types) {
    const meta = resolveEventMeta(type);
    assert.equal(meta.category, "CLOUD", `${type} should resolve to CLOUD category`);
    assert.ok(meta.siemType, `${type} should have a siemType`);
  }
});
