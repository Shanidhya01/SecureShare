/**
 * Confidence-Based DLP scoring (extends Phase 5, does not replace it). Regex-only detection is
 * cheap but noisy - a Rapido ride receipt's "Ride ID: 4111111111111111"-shaped reference number
 * looks exactly like a credit card to a bare regex. Real enterprise DLP engines (Symantec,
 * Forcepoint, Microsoft Purview) layer three extra signals on top of the regex hit before ever
 * blocking:
 *
 *   1. Validation      - does the candidate satisfy a format-specific checksum (Luhn for cards)?
 *   2. Context analysis - do nearby words look like a card statement, or like an unrelated ID?
 *   3. Confidence score  - combine the above into a 0-100 score and a LOW/MEDIUM/HIGH risk level.
 *
 * This module is intentionally generic (not credit-card-specific) so any detector can opt in by
 * calling `scoreCandidate` from its own `detectWithConfidence` export - see creditCard.js for the
 * reference implementation. Detectors that don't need this (API keys, PEM blocks, etc.) are
 * unaffected and keep using their plain `detect()` export.
 */

// Words that make a nearby number/ID look like an actual payment card.
export const CARD_CONTEXT_KEYWORDS = [
  "visa",
  "mastercard",
  "master card",
  "rupay",
  "amex",
  "american express",
  "debit card",
  "credit card",
  "card number",
  "card no",
  "expiry",
  "expiration date",
  "cvv",
  "cvc",
  "valid thru",
  "valid till",
  "valid from",
  "payment card",
  "bank",
  "cardholder",
  "card holder",
  "account holder"
];

// Common non-card identifiers that happen to be long digit runs - the exact false-positive class
// this feature exists to fix (Rapido/Uber ride receipts, invoices, tracking numbers, etc.).
export const FALSE_POSITIVE_ID_KEYWORDS = [
  "ride id",
  "booking id",
  "invoice number",
  "invoice no",
  "receipt number",
  "receipt no",
  "reference number",
  "reference no",
  "tracking number",
  "tracking no",
  "order number",
  "order no",
  "application number",
  "vehicle number",
  "employee id",
  "student id",
  "roll number",
  "registration number",
  "ticket number",
  "upi transaction id",
  "gst invoice number",
  "transaction id"
];

const CONTEXT_WINDOW_CHARS = 60;

/** Grabs the text immediately surrounding a match, for keyword scanning and the risk report. */
export function getContextWindow(text, index, matchLength) {
  const start = Math.max(0, index - CONTEXT_WINDOW_CHARS);
  const end = Math.min(text.length, index + matchLength + CONTEXT_WINDOW_CHARS);
  return text.slice(start, end);
}

function findKeywordHits(contextLower, keywords) {
  return keywords.filter((keyword) => contextLower.includes(keyword));
}

/** @param {number} score 0-100 */
export function confidenceLevelForScore(score) {
  if (score > 70) return "HIGH";
  if (score > 40) return "MEDIUM";
  return "LOW";
}

/** Maps a confidence level to the Part 5 decision engine outcome. */
export function decisionForConfidenceLevel(level) {
  if (level === "HIGH") return { decision: "block", actions: ["Block Upload", "Log Event", "Create SIEM Event"] };
  if (level === "MEDIUM") return { decision: "warn", actions: ["Allow", "Warn User"] };
  return { decision: "allow", actions: ["Allow", "Log"] };
}

/**
 * Weighted confidence score for a regex-matched credit-card-shaped candidate:
 *   +40 regex match (baseline, always true here since this is only called on a regex hit)
 *   +40 Luhn checksum passed
 *   +20 card-related keywords found nearby
 *   Non-card identifier keywords nearby (Ride ID, Invoice Number, ...) override everything and
 *   push the candidate back down, since that's the exact false-positive this feature targets.
 *
 * @param {{ text: string, index: number, matchLength: number, luhnPass: boolean }} params
 */
export function scoreCreditCardCandidate({ text, index, matchLength, luhnPass }) {
  const context = getContextWindow(text, index, matchLength);
  const contextLower = context.toLowerCase();

  const cardHits = findKeywordHits(contextLower, CARD_CONTEXT_KEYWORDS);
  const falsePositiveHits = findKeywordHits(contextLower, FALSE_POSITIVE_ID_KEYWORDS);

  const reasons = [];
  let score = 40;
  reasons.push("Regex matched a candidate card-like number");

  if (luhnPass) {
    score += 40;
    reasons.push("Luhn checksum passed");
  } else {
    reasons.push("Luhn checksum failed");
  }

  if (cardHits.length > 0) {
    score += 20;
    reasons.push(`Nearby card-related keywords found: ${cardHits.join(", ")}`);
  } else {
    reasons.push("No nearby card-related keywords");
  }

  let falsePositive = false;
  if (falsePositiveHits.length > 0) {
    falsePositive = true;
    if (cardHits.length === 0) {
      // No card context at all, plus an explicit non-card identifier label nearby (e.g. "Ride
      // ID: 4111111111111111") - this is the textbook false positive, so confidence is zeroed
      // out regardless of what the regex/Luhn checks found.
      score = 0;
      reasons.push(`Nearby non-card identifier keywords found (${falsePositiveHits.join(", ")}) - treated as false positive`);
    } else {
      // Ambiguous: both a card keyword and a non-card ID keyword are nearby. Penalize rather
      // than zero out, since this could be a legitimate statement that also references an
      // order/invoice number.
      score = Math.max(0, score - 30);
      reasons.push(`Nearby non-card identifier keywords found (${falsePositiveHits.join(", ")}) - confidence reduced`);
    }
  }

  score = Math.max(0, Math.min(100, score));
  const level = confidenceLevelForScore(score);

  return { score, level, reasons, context: context.trim(), falsePositive };
}
