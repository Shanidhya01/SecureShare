export const id = "passport";
export const label = "Passport Number";
export const category = "PII";
export const severity = "High";

// Generic passport-number heuristic: 1-2 leading letters followed by 6-9 digits. Passport
// formats vary widely by issuing country and this deliberately broad pattern trades precision
// for recall - it will over-match alphanumeric IDs of similar shape (documented limitation,
// see SECURITY.md). Kept as a single, conservative pattern rather than per-country rules.
const PATTERN = /\b[A-Z]{1,2}[0-9]{6,9}\b/g;

export function detect(text) {
  return text.match(PATTERN) || [];
}
