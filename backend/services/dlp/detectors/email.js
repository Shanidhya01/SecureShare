export const id = "email";
export const label = "Email Address";
export const category = "PII";
export const severity = "Low";

const PATTERN = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

export function detect(text) {
  return text.match(PATTERN) || [];
}
