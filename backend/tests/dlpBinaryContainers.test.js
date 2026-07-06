/**
 * Regression tests for a real bug found while debugging the confidence-based DLP engine: PDF (and
 * other binary-container) files were being misclassified as scannable text by
 * extractScannableText()'s printable-byte-ratio fallback, because a PDF's early object/xref
 * structure is mostly printable ASCII even though the file as a whole is binary. That caused the
 * DLP engine to regex/Luhn-scan raw compressed stream bytes and the xref table's zero-padded
 * offset numbers (e.g. "0000000015 00000 n"), producing dozens of spurious HIGH-confidence
 * "credit card" findings - with no real surrounding context, since the actual document text lives
 * inside compressed streams, not the decoded byte soup - and blocking harmless receipts/invoices.
 *
 * Fix: services/dlp/textFileSupport.js now sniffs magic bytes via utils/magicBytes.js and hard-
 * excludes known binary containers (PDF, ZIP/Office, RAR, 7z, gzip, executables, RTF) from the
 * printable-ratio fallback, the same way it already excludes images by extension/MIME.
 *
 * Run with: node --test backend/tests
 */
import test from "node:test";
import assert from "node:assert/strict";
import PDFDocument from "pdfkit";
import { extractScannableText } from "../services/dlp/textFileSupport.js";
import { runDLPScan } from "../services/dlp/dlpEngine.js";

function buildPdf(lines) {
  return new Promise((resolve) => {
    const doc = new PDFDocument();
    const chunks = [];
    doc.on("data", (c) => chunks.push(c));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    for (const line of lines) doc.text(line);
    doc.end();
  });
}

test("a PDF receipt is skipped as unsupported binary content, not misread as garbage text", async () => {
  const buffer = await buildPdf(["Rapido Booking Receipt", "Ride ID: 4111111111111111", "Fare: Rs. 128"]);
  const extraction = extractScannableText(buffer, { originalFilename: "receipt.pdf", claimedMimeType: "application/pdf" });
  assert.equal(extraction.supported, false);
  assert.equal(extraction.reason, "binary_or_unsupported_type");
});

test("runDLPScan allows a PDF receipt outright (skipped, no spurious credit-card findings)", async () => {
  const buffer = await buildPdf(["Rapido Booking Receipt", "Ride ID: 4111111111111111", "Fare: Rs. 128"]);
  const result = runDLPScan(buffer, { originalFilename: "receipt.pdf", claimedMimeType: "application/pdf" });
  assert.equal(result.supported, false);
  assert.equal(result.decision, "allow");
  assert.deepEqual(result.findings, []);
});

test("runDLPScan allows a PDF invoice outright, even one containing a real 16-digit-shaped number", async () => {
  const buffer = await buildPdf(["Invoice Number: 4111111111111111", "Total Due: $42.00"]);
  const result = runDLPScan(buffer, { originalFilename: "invoice.pdf", claimedMimeType: "application/pdf" });
  assert.equal(result.supported, false);
  assert.equal(result.decision, "allow");
});

test("a PDF is identified as binary_or_unsupported_type even when the claimed MIME type is text/plain", async () => {
  // A mismatched/spoofed MIME type shouldn't matter - magic-byte sniffing wins.
  const buffer = await buildPdf(["just some text"]);
  const extraction = extractScannableText(buffer, { originalFilename: "not-really.txt", claimedMimeType: "text/plain" });
  assert.equal(extraction.supported, false);
});
