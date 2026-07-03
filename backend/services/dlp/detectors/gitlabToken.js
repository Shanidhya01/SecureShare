export const id = "gitlab_token";
export const label = "GitLab Personal Access Token";
export const category = "Source Control Credentials";
export const severity = "Critical";

const PATTERN = /\bglpat-[A-Za-z0-9_-]{20,}\b/g;

export function detect(text) {
  return text.match(PATTERN) || [];
}
