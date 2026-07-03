export const id = "jwt_token";
export const label = "JWT Token";
export const category = "Session/Auth Tokens";
export const severity = "High";

// header.payload.signature, each base64url. Requires a plausible base64url-encoded JSON header
// (starts with "eyJ") to cut down on matching arbitrary dot-separated tokens.
const PATTERN = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;

export function detect(text) {
  return text.match(PATTERN) || [];
}
