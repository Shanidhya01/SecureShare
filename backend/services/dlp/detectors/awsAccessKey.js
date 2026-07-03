export const id = "aws_access_key";
export const label = "AWS Access Key ID";
export const category = "Cloud Credentials";
export const severity = "Critical";

const PATTERN = /\b(?:AKIA|ASIA|AIDA|AROA|AGPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b/g;

export function detect(text) {
  return text.match(PATTERN) || [];
}
