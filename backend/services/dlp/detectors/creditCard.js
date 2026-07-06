import { scoreCreditCardCandidate, decisionForConfidenceLevel } from "../confidenceEngine.js";

export const id = "credit_card";
export const label = "Credit Card Number";
export const category = "Financial";
export const severity = "Critical";

// Candidate sequences: 13-19 digits, optionally separated by spaces or dashes in groups.
const CANDIDATE_PATTERN = /\b(?:\d[ -]?){12,18}\d\b/g;

function luhnValid(digits) {
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

// Kept exactly as-is for backward compatibility: plain regex+Luhn match, no confidence scoring.
// dlpEngine.js prefers detectWithConfidence() below when present; this remains the fallback and
// is still exercised directly by existing callers/tests.
export function detect(text) {
  const candidates = text.match(CANDIDATE_PATTERN) || [];
  const found = [];
  for (const candidate of candidates) {
    const digits = candidate.replace(/[ -]/g, "");
    if (digits.length < 13 || digits.length > 19) continue;
    if (luhnValid(digits)) found.push(candidate);
  }
  return found;
}

/**
 * Confidence-based variant (Part 1-5 of the confidence-based DLP engine): every regex candidate
 * (Luhn-valid or not) is scored using validation + surrounding context, instead of a binary
 * match/no-match. This is what lets a Rapido ride receipt's "Ride ID: 4111 1111 1111 1111" be
 * recognized as a false positive instead of an auto-blocked credit card, while a real card number
 * next to "Card Number: ... Expiry ... CVV" scores HIGH and still gets blocked.
 *
 * @param {string} text
 * @returns {Array<{value: string, luhnPass: boolean, confidenceScore: number, confidenceLevel: string,
 *   reasons: string[], context: string, falsePositive: boolean, decision: string}>}
 */
export function detectWithConfidence(text) {
  const regex = new RegExp(CANDIDATE_PATTERN.source, "g");
  const results = [];
  const seen = new Set();
  let match;

  while ((match = regex.exec(text)) !== null) {
    const rawMatch = match[0];
    const digits = rawMatch.replace(/[ -]/g, "");
    if (digits.length < 13 || digits.length > 19) continue;
    if (seen.has(rawMatch)) continue;
    seen.add(rawMatch);

    const luhnPass = luhnValid(digits);
    const scoring = scoreCreditCardCandidate({
      text,
      index: match.index,
      matchLength: rawMatch.length,
      luhnPass
    });
    const { decision } = decisionForConfidenceLevel(scoring.level);

    results.push({
      value: rawMatch,
      luhnPass,
      confidenceScore: scoring.score,
      confidenceLevel: scoring.level,
      reasons: scoring.reasons,
      context: scoring.context,
      falsePositive: scoring.falsePositive,
      decision
    });
  }

  return results;
}
