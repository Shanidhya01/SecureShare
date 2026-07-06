export const id = "iban";
export const label = "IBAN (International Bank Account Number)";
export const category = "Financial";
export const severity = "High";

// Country code (2 letters) + 2 check digits + up to 30 alphanumeric BBAN characters, optionally
// grouped in blocks of 4 the way banks print them (e.g. "DE44 5001 0517 5407 3249 31").
const PATTERN = /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/g;

export function detect(text) {
  const matches = text.match(PATTERN) || [];
  return matches.filter((m) => {
    const compact = m.replace(/\s+/g, "");
    return compact.length >= 15 && compact.length <= 34;
  });
}
