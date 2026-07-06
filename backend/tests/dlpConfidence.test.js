/**
 * Confidence-Based DLP engine tests (extends dlp.test.js). Covers Luhn validation, context
 * analysis, false-positive ID rejection, confidence scoring/decision mapping, and the new
 * IBAN/SWIFT detectors - see backend/services/dlp/confidenceEngine.js.
 * Run with: node --test backend/tests
 */
import test from "node:test";
import assert from "node:assert/strict";
import { runDLPScan } from "../services/dlp/dlpEngine.js";
import * as creditCard from "../services/dlp/detectors/creditCard.js";
import * as aadhaar from "../services/dlp/detectors/aadhaar.js";
import * as pan from "../services/dlp/detectors/pan.js";
import * as passport from "../services/dlp/detectors/passport.js";
import * as iban from "../services/dlp/detectors/iban.js";
import * as swift from "../services/dlp/detectors/swift.js";

const meta = (filename, mime = "text/plain") => ({ originalFilename: filename, claimedMimeType: mime });

test("real credit card with card context is HIGH confidence and blocked", () => {
  const buffer = Buffer.from(
    "Payment Card Statement\nCardholder: Jane Doe\nCard Number: 4111 1111 1111 1111\nExpiry: 09/28  CVV: 123\n",
    "utf8"
  );
  const result = runDLPScan(buffer, meta("statement.txt"));
  const finding = result.findings.find((f) => f.detectorId === "credit_card");
  assert.ok(finding, "expected a credit_card finding");
  assert.equal(finding.confidenceLevel, "HIGH");
  assert.equal(result.decision, "block");
});

test("random 16-digit number failing Luhn is allowed (LOW confidence)", () => {
  const buffer = Buffer.from("Random number: 1234567812345678\n", "utf8");
  const result = runDLPScan(buffer, meta("notes.txt"));
  const finding = result.findings.find((f) => f.detectorId === "credit_card");
  if (finding) {
    assert.equal(finding.confidenceLevel, "LOW");
  }
  assert.equal(result.decision, "allow");
});

test("Rapido-style Ride ID receipt is allowed, not flagged as a blocked credit card", () => {
  const buffer = Buffer.from(
    "Rapido Booking Receipt\nRide ID: 4111111111111111\nFare: Rs. 128\nThank you for riding with us.\n",
    "utf8"
  );
  const result = runDLPScan(buffer, meta("receipt.txt"));
  assert.equal(result.decision, "allow");
});

test("Invoice Number receipt is allowed", () => {
  const buffer = Buffer.from("Invoice Number: 4111111111111111\nTotal Due: $42.00\n", "utf8");
  const result = runDLPScan(buffer, meta("invoice.txt"));
  assert.equal(result.decision, "allow");
});

test("Booking receipt with Booking ID is allowed", () => {
  const buffer = Buffer.from("Booking ID: 4111111111111111\nHotel: Example Inn\n", "utf8");
  const result = runDLPScan(buffer, meta("booking.txt"));
  assert.equal(result.decision, "allow");
});

test("creditCard.detectWithConfidence flags false positive near non-card ID keywords", () => {
  const scored = creditCard.detectWithConfidence("Transaction ID: 4111111111111111 completed successfully.");
  assert.equal(scored.length, 1);
  assert.equal(scored[0].falsePositive, true);
  assert.equal(scored[0].confidenceLevel, "LOW");
  assert.equal(scored[0].decision, "allow");
});

test("creditCard.detect() backward compatibility is unchanged", () => {
  const valid = creditCard.detect("card: 4111111111111111");
  assert.equal(valid.length, 1);
  const invalid = creditCard.detect("card: 4111111111111112");
  assert.equal(invalid.length, 0);
});

test("PAN card is detected", () => {
  const found = pan.detect("PAN: ABCDE1234F");
  assert.equal(found.length, 1);
});

test("Aadhaar number is detected", () => {
  const found = aadhaar.detect("Aadhaar: 234512345678");
  assert.equal(found.length, 1);
});

test("Passport number is detected", () => {
  const found = passport.detect("Passport No: A1234567");
  assert.equal(found.length, 1);
});

test("IBAN is detected", () => {
  const found = iban.detect("IBAN: DE44 5001 0517 5407 3249 31");
  assert.equal(found.length, 1);
});

test("SWIFT/BIC is detected only with nearby context keyword", () => {
  const found = swift.detect("SWIFT Code: DEUTDEFF500");
  assert.equal(found.length, 1);

  const noContext = swift.detect("Random uppercase token: DEUTDEFF500 in a sentence.");
  assert.equal(noContext.length, 0);
});

test("runDLPScan risk report includes confidence/reasons/decision per finding", () => {
  const buffer = Buffer.from("Card Number: 4111 1111 1111 1111\nCVV: 123\n", "utf8");
  const result = runDLPScan(buffer, meta("card.txt"));
  const report = result.riskReport.find((r) => r.detectorId === "credit_card");
  assert.ok(report);
  assert.ok(typeof report.confidence === "number");
  assert.ok(Array.isArray(report.reasons) && report.reasons.length > 0);
  assert.ok(["allow", "warn", "require_approval", "block"].includes(report.decision));
});
