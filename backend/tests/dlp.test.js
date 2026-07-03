/**
 * Sanity tests for the Phase 5 DLP engine, using Node's built-in test runner (no new
 * dependency needed - the repo has no test framework installed, see backend/package.json).
 * Run with: node --test backend/tests
 */
import test from "node:test";
import assert from "node:assert/strict";
import { runDLPScan } from "../services/dlp/dlpEngine.js";
import { resolveDecision } from "../services/dlp/dlpPolicyConfig.js";
import { maskValue } from "../services/dlp/maskUtils.js";
import * as creditCard from "../services/dlp/detectors/creditCard.js";
import * as awsAccessKey from "../services/dlp/detectors/awsAccessKey.js";
import * as email from "../services/dlp/detectors/email.js";
import * as pemPrivateKey from "../services/dlp/detectors/pemPrivateKey.js";
import * as envSecret from "../services/dlp/detectors/envSecret.js";

const meta = (filename, mime = "text/plain") => ({ originalFilename: filename, claimedMimeType: mime });

test("email detector finds addresses", () => {
  const found = email.detect("Contact us at support@example.com for help.");
  assert.deepEqual(found, ["support@example.com"]);
});

test("credit card detector validates via Luhn", () => {
  // 4111111111111111 is a well-known Luhn-valid test Visa number.
  const valid = creditCard.detect("card: 4111111111111111");
  assert.equal(valid.length, 1);

  // Same length, deliberately invalid checksum.
  const invalid = creditCard.detect("card: 4111111111111112");
  assert.equal(invalid.length, 0);
});

test("aws access key detector matches AKIA-prefixed keys", () => {
  const found = awsAccessKey.detect("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
  assert.equal(found.length, 1);
  assert.equal(found[0], "AKIAIOSFODNN7EXAMPLE");
});

test("pem private key detector matches BEGIN/END block", () => {
  const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----";
  const found = pemPrivateKey.detect(pem);
  assert.equal(found.length, 1);
});

test("env secret detector ignores placeholders", () => {
  const found = envSecret.detect("API_SECRET_KEY=changeme\nSTRIPE_SECRET_KEY=sk_live_abcdef123456");
  assert.equal(found.length, 1);
  assert.match(found[0], /STRIPE_SECRET_KEY/);
});

test("maskValue never returns the raw value for non-trivial strings", () => {
  const masked = maskValue("AKIAIOSFODNN7EXAMPLE");
  assert.notEqual(masked, "AKIAIOSFODNN7EXAMPLE");
  assert.ok(masked.includes("*"));
});

test("resolveDecision escalates to block when any finding is a hard-blocked detector", () => {
  const { decision } = resolveDecision([
    { detectorId: "email", severity: "Low" },
    { detectorId: "aws_secret_key", severity: "Critical" }
  ]);
  assert.equal(decision, "block");
});

test("resolveDecision allows when there are no findings", () => {
  const { decision } = resolveDecision([]);
  assert.equal(decision, "allow");
});

test("runDLPScan skips binary/unsupported files gracefully", () => {
  const binary = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00]); // MZ header
  const result = runDLPScan(binary, meta("app.exe", "application/octet-stream"));
  assert.equal(result.supported, false);
  assert.equal(result.decision, "allow");
  assert.deepEqual(result.findings, []);
});

test("runDLPScan blocks a text file containing an AWS access key", () => {
  const buffer = Buffer.from("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n", "utf8");
  const result = runDLPScan(buffer, meta("config.env", "text/plain"));
  assert.equal(result.supported, true);
  assert.equal(result.decision, "block");
  assert.ok(result.matchedPatterns.includes("aws_access_key"));
  // Raw secret must never appear in the persisted findings.
  const serialized = JSON.stringify(result.findings);
  assert.ok(!serialized.includes("AKIAIOSFODNN7EXAMPLE"));
});

test("runDLPScan allows a clean text file with no sensitive content", () => {
  const buffer = Buffer.from("This is just a regular note with nothing sensitive in it.", "utf8");
  const result = runDLPScan(buffer, meta("notes.txt", "text/plain"));
  assert.equal(result.decision, "allow");
  assert.deepEqual(result.findings, []);
});
