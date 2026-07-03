export const id = "aadhaar";
export const label = "Aadhaar Number (India)";
export const category = "PII";
export const severity = "High";

// 12-digit Indian national ID, conventionally displayed as three groups of 4. The first digit
// is never 0 or 1 per UIDAI's numbering scheme - used here as a cheap false-positive filter,
// not a full Verhoeff checksum validation (documented limitation, see SECURITY.md).
const PATTERN = /\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b/g;

export function detect(text) {
  return text.match(PATTERN) || [];
}
