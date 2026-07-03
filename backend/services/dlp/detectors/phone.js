export const id = "phone";
export const label = "Phone Number";
export const category = "PII";
export const severity = "Low";

// Requires an explicit country code or a recognizable separated grouping, to keep false
// positives (invoice numbers, IDs, etc.) low. Matches e.g. +1 415-555-2671, +91 98765 43210,
// (415) 555-2671.
const PATTERN = /(?:\+\d{1,3}[\s.-]?)(?:\(\d{2,4}\)[\s.-]?)?\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b|\(\d{3}\)[\s.-]?\d{3}[\s.-]?\d{4}\b/g;

export function detect(text) {
  return text.match(PATTERN) || [];
}
