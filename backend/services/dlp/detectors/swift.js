// 4-letter bank code + 2-letter country code + 2-char location code + optional 3-char branch code.
// This shape alone is common in ordinary uppercase text (product codes, acronyms), so - like the
// confidence-based credit card detector - a match only counts if a "swift"/"bic" label is nearby.
// See backend/services/dlp/confidenceEngine.js for the same context-analysis idea applied here.
export const id = "swift_bic";
export const label = "SWIFT/BIC Code";
export const category = "Financial";
export const severity = "Medium";

const PATTERN = /\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/g;
const CONTEXT_KEYWORDS = ["swift", "bic"];
const CONTEXT_WINDOW_CHARS = 40;

export function detect(text) {
  const regex = new RegExp(PATTERN.source, "g");
  const matches = [];
  let m;
  while ((m = regex.exec(text)) !== null) {
    const start = Math.max(0, m.index - CONTEXT_WINDOW_CHARS);
    const end = Math.min(text.length, m.index + m[0].length + CONTEXT_WINDOW_CHARS);
    const context = text.slice(start, end).toLowerCase();
    if (CONTEXT_KEYWORDS.some((k) => context.includes(k))) {
      matches.push(m[0]);
    }
  }
  return matches;
}
