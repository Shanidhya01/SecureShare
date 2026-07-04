/**
 * Sanity tests for the Phase 8 SOAR engine, using Node's built-in test runner (same convention as
 * backend/tests/correlationEngine.test.js and backend/tests/dlp.test.js). These avoid a live
 * MongoDB connection wherever possible - matchRules/evaluateCondition/eventTriggerFor are pure,
 * runPlaybook is tested with injected stub action handlers, and the runSoarEngine recursion guard
 * is tested directly since it returns before touching the DB for category "AUTOMATION" events.
 * Run with: node --test backend/tests
 */
import test from "node:test";
import assert from "node:assert/strict";
import { matchRules, evaluateCondition, eventTriggerFor } from "../services/soar/ruleMatcher.js";
import { runPlaybook } from "../services/soar/playbookRunner.js";
import { runSoarEngine } from "../services/soar/soarEngine.js";

/* ------------------------------- eventTriggerFor ------------------------------- */

test("eventTriggerFor maps known SecurityEvent types to their trigger", () => {
  assert.equal(eventTriggerFor({ type: "threat_found" }), "THREAT_FOUND");
  assert.equal(eventTriggerFor({ type: "ioc_match" }), "IOC_MATCH");
  assert.equal(eventTriggerFor({ type: "threat_intel_match" }), "IOC_MATCH");
  assert.equal(eventTriggerFor({ type: "dlp_blocked" }), "DLP_BLOCK");
  assert.equal(eventTriggerFor({ type: "signature_invalid" }), "SIGNATURE_FAILED");
  assert.equal(eventTriggerFor({ type: "yara_match" }), "YARA_MATCH");
  assert.equal(eventTriggerFor({ type: "new_device" }), "NEW_DEVICE");
});

test("eventTriggerFor returns null for unmapped or unknown types", () => {
  assert.equal(eventTriggerFor({ type: "upload" }), null);
  assert.equal(eventTriggerFor({ type: "totally_unknown" }), null);
});

test("eventTriggerFor maps mitre_mapping to MITRE_CRITICAL only for critical tactics", () => {
  const critical = eventTriggerFor({ type: "mitre_mapping", metadata: { techniques: [{ tactic: "Impact" }] } });
  assert.equal(critical, "MITRE_CRITICAL");

  const nonCritical = eventTriggerFor({ type: "mitre_mapping", metadata: { techniques: [{ tactic: "Discovery" }] } });
  assert.equal(nonCritical, null);
});

/* ------------------------------- evaluateCondition ------------------------------- */

test("evaluateCondition supports comparison operators", () => {
  const event = { severity: "HIGH", metadata: { matchCount: 5 } };
  assert.equal(evaluateCondition({ field: "severity", operator: "eq", value: "HIGH" }, event), true);
  assert.equal(evaluateCondition({ field: "severity", operator: "neq", value: "LOW" }, event), true);
  assert.equal(evaluateCondition({ field: "metadata.matchCount", operator: "gte", value: 5 }, event), true);
  assert.equal(evaluateCondition({ field: "metadata.matchCount", operator: "gt", value: 5 }, event), false);
  assert.equal(evaluateCondition({ field: "metadata.matchCount", operator: "lt", value: 10 }, event), true);
});

test("evaluateCondition supports contains and in", () => {
  const event = { metadata: { tags: ["ransomware", "phishing"] } };
  assert.equal(evaluateCondition({ field: "metadata.tags", operator: "contains", value: "ransomware" }, event), true);
  assert.equal(evaluateCondition({ field: "severity", operator: "in", value: ["HIGH", "CRITICAL"] }, { severity: "HIGH" }), true);
  assert.equal(evaluateCondition({ field: "severity", operator: "in", value: ["HIGH", "CRITICAL"] }, { severity: "LOW" }), false);
});

/* ------------------------------- matchRules ------------------------------- */

const rule = (overrides) => ({ enabled: true, trigger: "DLP_BLOCK", conditions: [], priority: 100, ...overrides });

test("matchRules filters by trigger and enabled flag", () => {
  const event = { type: "dlp_blocked" };
  const rules = [
    rule({ name: "a" }),
    rule({ name: "b", enabled: false }),
    rule({ name: "c", trigger: "THREAT_FOUND" })
  ];
  const matched = matchRules(event, rules);
  assert.equal(matched.length, 1);
  assert.equal(matched[0].name, "a");
});

test("matchRules evaluates conditions and sorts by priority", () => {
  const event = { type: "threat_found", severity: "CRITICAL" };
  const rules = [
    rule({ name: "low-priority", trigger: "THREAT_FOUND", priority: 50 }),
    rule({ name: "high-priority", trigger: "THREAT_FOUND", priority: 10 }),
    rule({ name: "wrong-condition", trigger: "THREAT_FOUND", conditions: [{ field: "severity", operator: "eq", value: "LOW" }] })
  ];
  const matched = matchRules(event, rules);
  assert.deepEqual(matched.map((r) => r.name), ["high-priority", "low-priority"]);
});

test("matchRules returns empty array when the event has no mapped trigger", () => {
  assert.deepEqual(matchRules({ type: "upload" }, [rule({ trigger: "THREAT_FOUND" })]), []);
});

/* ------------------------------- runPlaybook ------------------------------- */

test("runPlaybook runs steps in order and reports completed status", async () => {
  const order = [];
  const handlers = {
    stepA: async () => { order.push("A"); return { success: true, detail: "ok-a" }; },
    stepB: async () => { order.push("B"); return { success: true, detail: "ok-b" }; }
  };
  const { results, status } = await runPlaybook({ steps: [{ type: "stepA" }, { type: "stepB" }] }, {}, {}, handlers);
  assert.deepEqual(order, ["A", "B"]);
  assert.equal(status, "completed");
  assert.equal(results.length, 2);
  assert.ok(results.every((r) => r.success));
});

test("runPlaybook marks status 'partial' when some actions fail but not all, and continues past a continueOnFailure step", async () => {
  const handlers = {
    ok: async () => ({ success: true, detail: "fine" }),
    bad: async () => ({ success: false, detail: "boom" })
  };
  const { results, status } = await runPlaybook(
    { steps: [{ type: "bad", continueOnFailure: true }, { type: "ok" }] },
    {},
    {},
    handlers
  );
  assert.equal(results.length, 2);
  assert.equal(status, "partial");
});

test("runPlaybook stops early when a non-continueOnFailure step fails", async () => {
  const ranSteps = [];
  const handlers = {
    bad: async () => { ranSteps.push("bad"); return { success: false, detail: "boom" }; },
    neverRuns: async () => { ranSteps.push("neverRuns"); return { success: true, detail: "unreachable" }; }
  };
  const { results, status } = await runPlaybook(
    { steps: [{ type: "bad", continueOnFailure: false }, { type: "neverRuns" }] },
    {},
    {},
    handlers
  );
  assert.deepEqual(ranSteps, ["bad"]);
  assert.equal(results.length, 1);
  assert.equal(status, "failed");
});

test("runPlaybook handles an unknown action type as a recorded failure, not a thrown error", async () => {
  const { results, status } = await runPlaybook({ steps: [{ type: "doesNotExist" }] }, {}, {}, {});
  assert.equal(results[0].success, false);
  assert.match(results[0].detail, /Unknown action type/);
  assert.equal(status, "failed");
});

test("runPlaybook catches a throwing handler and records it as a failure", async () => {
  const handlers = { explodes: async () => { throw new Error("kaboom"); } };
  const { results, status } = await runPlaybook({ steps: [{ type: "explodes" }] }, {}, {}, handlers);
  assert.equal(results[0].success, false);
  assert.equal(results[0].detail, "kaboom");
  assert.equal(status, "failed");
});

/* ------------------------------- runSoarEngine recursion guard ------------------------------- */

test("runSoarEngine no-ops (without touching the DB) for events it generated itself", async () => {
  // category "AUTOMATION" events are what SOAR's own actions/SIEM events carry - the guard at the
  // top of runSoarEngine must return before any AutomationRule.find() call, so this resolves
  // immediately even with no live MongoDB connection in this test run.
  await assert.doesNotReject(runSoarEngine({ category: "AUTOMATION", type: "playbook_completed" }));
});

test("runSoarEngine no-ops for a null/undefined event", async () => {
  await assert.doesNotReject(runSoarEngine(null));
  await assert.doesNotReject(runSoarEngine(undefined));
});
