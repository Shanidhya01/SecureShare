export const id = "password_assignment";
export const label = "Hardcoded Password";
export const category = "Credentials";
export const severity = "High";

// Matches common "key = value" / "key: value" assignments where the key looks like a password
// field and the value is a non-trivial literal (quoted or bare token), e.g.:
//   password = "hunter2"        pwd: 's3cr3t!'        PASSWORD=Tr0ub4dor&3
const PATTERN = /\b(?:password|passwd|pwd)\s*[:=]\s*(["'`]?)([^\s"'`]{4,})\1/gi;

const PLACEHOLDER_VALUES = new Set([
  "changeme", "changeit", "placeholder", "xxxxx", "yourpassword", "your_password",
  "example", "null", "undefined", "none", "todo", "redacted", "***"
]);

export function detect(text) {
  const found = [];
  let match;
  const re = new RegExp(PATTERN);
  while ((match = re.exec(text)) !== null) {
    const value = match[2];
    if (PLACEHOLDER_VALUES.has(value.toLowerCase())) continue;
    found.push(match[0]);
  }
  return found;
}
