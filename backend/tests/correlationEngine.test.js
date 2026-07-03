/**
 * Sanity tests for the Phase 6 SIEM correlation engine's pure rule evaluation, using Node's
 * built-in test runner (see backend/tests/dlp.test.js for the same pattern).
 * Run with: node --test backend/tests
 */
import test from "node:test";
import assert from "node:assert/strict";
import { evaluateRules } from "../services/siem/correlationEngine.js";

const t = (isoOffsetMinutes) => new Date(Date.now() + isoOffsetMinutes * 60 * 1000);

test("malware-blocked-download: matches when a download is denied after quarantine on the same file", () => {
  const fileId = "file-1";
  const quarantineEvent = { _id: "e1", siemType: "FILE_QUARANTINED", severity: "CRITICAL", file: fileId, createdAt: t(-60) };
  const deniedEvent = { _id: "e2", siemType: "DOWNLOAD_DENIED", severity: "HIGH", file: fileId, createdAt: t(0) };

  const matches = evaluateRules([quarantineEvent, deniedEvent], deniedEvent);
  const match = matches.find((m) => m.ruleId === "malware-blocked-download");

  assert.ok(match, "expected malware-blocked-download to match");
  assert.equal(match.severity, "CRITICAL");
  assert.deepEqual(match.matchedEventIds.sort(), ["e1", "e2"]);
});

test("malware-blocked-download: does not match for a different file", () => {
  const quarantineEvent = { _id: "e1", siemType: "FILE_QUARANTINED", severity: "CRITICAL", file: "file-1", createdAt: t(-60) };
  const deniedEvent = { _id: "e2", siemType: "DOWNLOAD_DENIED", severity: "HIGH", file: "file-2", createdAt: t(0) };

  const matches = evaluateRules([quarantineEvent, deniedEvent], deniedEvent);
  assert.equal(matches.find((m) => m.ruleId === "malware-blocked-download"), undefined);
});

test("malware-blocked-download: does not match if the quarantine event is more than 24h old", () => {
  const quarantineEvent = { _id: "e1", siemType: "FILE_QUARANTINED", severity: "CRITICAL", file: "file-1", createdAt: t(-25 * 60) };
  const deniedEvent = { _id: "e2", siemType: "DOWNLOAD_DENIED", severity: "HIGH", file: "file-1", createdAt: t(0) };

  const matches = evaluateRules([quarantineEvent, deniedEvent], deniedEvent);
  assert.equal(matches.find((m) => m.ruleId === "malware-blocked-download"), undefined);
});

test("repeated-dlp-violations: matches at 3+ DLP events within the last hour", () => {
  const events = [
    { _id: "d1", siemType: "DLP_BLOCK", severity: "HIGH", createdAt: t(-50) },
    { _id: "d2", siemType: "DLP_WARNING", severity: "MEDIUM", createdAt: t(-20) },
    { _id: "d3", siemType: "DLP_BLOCK", severity: "HIGH", createdAt: t(0) }
  ];
  const newEvent = events[2];

  const matches = evaluateRules(events, newEvent);
  const match = matches.find((m) => m.ruleId === "repeated-dlp-violations");

  assert.ok(match, "expected repeated-dlp-violations to match");
  assert.equal(match.matchedEventIds.length, 3);
});

test("repeated-dlp-violations: does not match with only 2 events", () => {
  const events = [
    { _id: "d1", siemType: "DLP_BLOCK", severity: "HIGH", createdAt: t(-20) },
    { _id: "d2", siemType: "DLP_WARNING", severity: "MEDIUM", createdAt: t(0) }
  ];

  const matches = evaluateRules(events, events[1]);
  assert.equal(matches.find((m) => m.ruleId === "repeated-dlp-violations"), undefined);
});

test("new-device-then-denied: matches when a denial follows a new device within the hour", () => {
  const deviceEvent = { _id: "n1", siemType: "DEVICE_NEW", severity: "INFO", createdAt: t(-30) };
  const deniedEvent = { _id: "n2", siemType: "DOWNLOAD_DENIED", severity: "MEDIUM", file: "file-3", createdAt: t(0) };

  const matches = evaluateRules([deviceEvent, deniedEvent], deniedEvent);
  const match = matches.find((m) => m.ruleId === "new-device-then-denied");

  assert.ok(match, "expected new-device-then-denied to match");
  assert.deepEqual(match.matchedEventIds.sort(), ["n1", "n2"]);
});

test("new-device-then-denied: does not match beyond the 1h window", () => {
  const deviceEvent = { _id: "n1", siemType: "DEVICE_NEW", severity: "INFO", createdAt: t(-90) };
  const deniedEvent = { _id: "n2", siemType: "DOWNLOAD_DENIED", severity: "MEDIUM", file: "file-3", createdAt: t(0) };

  const matches = evaluateRules([deviceEvent, deniedEvent], deniedEvent);
  assert.equal(matches.find((m) => m.ruleId === "new-device-then-denied"), undefined);
});

test("unrelated event types produce no matches", () => {
  const loginEvent = { _id: "l1", siemType: "LOGIN", severity: "INFO", createdAt: t(0) };
  const matches = evaluateRules([loginEvent], loginEvent);
  assert.deepEqual(matches, []);
});
