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
