export const id = "pan";
export const label = "PAN Number (India)";
export const category = "PII";
export const severity = "High";

// Indian Permanent Account Number: 5 letters, 4 digits, 1 letter (e.g. ABCDE1234F).
const PATTERN = /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g;

export function detect(text) {
  return text.match(PATTERN) || [];
}
