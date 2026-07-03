export const id = "google_api_key";
export const label = "Google API Key";
export const category = "Cloud Credentials";
export const severity = "Critical";

const PATTERN = /\bAIza[0-9A-Za-z_-]{35}\b/g;

export function detect(text) {
  return text.match(PATTERN) || [];
}
