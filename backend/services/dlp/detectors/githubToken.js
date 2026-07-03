export const id = "github_token";
export const label = "GitHub Personal Access Token";
export const category = "Source Control Credentials";
export const severity = "Critical";

// ghp_ (classic PAT), gho_ (OAuth), ghu_ (user-to-server), ghs_ (server-to-server), ghr_ (refresh)
const PATTERN = /\bgh[posur]_[A-Za-z0-9]{36,}\b/g;

export function detect(text) {
  return text.match(PATTERN) || [];
}
