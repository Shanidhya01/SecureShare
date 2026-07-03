export const id = "env_secret";
export const label = ".env-style Secret";
export const category = "Credentials";
export const severity = "High";

// Matches KEY=VALUE lines (dotenv style) where KEY names something secret-shaped and VALUE is a
// non-empty, non-placeholder literal. Deliberately excludes plain "PASSWORD"/"password" keys,
// which are already covered by passwordAssignment.js to avoid double-counting the same line.
const KEY_HINT = /^[A-Za-z0-9_]*(SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|ACCESS[_-]?KEY|CLIENT[_-]?SECRET)[A-Za-z0-9_]*$/i;
const LINE_PATTERN = /^\s*([A-Za-z0-9_]+)\s*=\s*(["'`]?)(\S+?)\2\s*$/gm;

const PLACEHOLDER_VALUES = new Set([
  "changeme", "changeit", "placeholder", "xxxxx", "your_key_here", "your_secret_here",
  "example", "null", "undefined", "none", "todo", "redacted", "***", ""
]);

export function detect(text) {
  const found = [];
  let match;
  const re = new RegExp(LINE_PATTERN);
  while ((match = re.exec(text)) !== null) {
    const [, key, , value] = match;
    if (!KEY_HINT.test(key)) continue;
    if (PLACEHOLDER_VALUES.has(value.toLowerCase())) continue;
    if (value.length < 6) continue;
    found.push(match[0].trim());
  }
  return found;
}
