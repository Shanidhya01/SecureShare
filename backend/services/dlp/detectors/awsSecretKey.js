export const id = "aws_secret_key";
export const label = "AWS Secret Access Key";
export const category = "Cloud Credentials";
export const severity = "Critical";

// A bare 40-char base64-alphabet string is too generic to flag on its own (matches all sorts of
// hashes/tokens), so this only fires when such a string appears near an AWS-secret-shaped key
// name (aws_secret_access_key, AWS_SECRET_ACCESS_KEY, secretAccessKey, ...) within ~80 chars.
const KEY_HINT = /aws[_-]?secret[_-]?access[_-]?key/i;
const CANDIDATE = /\b[A-Za-z0-9/+]{40}\b/g;

export function detect(text) {
  const found = [];
  let match;
  while ((match = CANDIDATE.exec(text)) !== null) {
    const windowStart = Math.max(0, match.index - 80);
    const context = text.slice(windowStart, match.index);
    if (KEY_HINT.test(context)) found.push(match[0]);
  }
  return found;
}
