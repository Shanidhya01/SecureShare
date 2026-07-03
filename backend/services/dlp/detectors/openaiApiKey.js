export const id = "openai_api_key";
export const label = "OpenAI API Key";
export const category = "AI/ML Credentials";
export const severity = "Critical";

// Covers legacy sk-... keys and the newer sk-proj-...  / sk-svcacct-... prefixed keys.
const PATTERN = /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/g;

export function detect(text) {
  return text.match(PATTERN) || [];
}
