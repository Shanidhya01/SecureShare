/**
 * Phase 8 (SOAR): reads the `isAdmin` convenience claim from the stored JWT to gate rule/playbook
 * management UI. This is a UI convenience only - the backend's requireAdmin middleware
 * (backend/middleware/requireAdmin.js) re-checks the User document on every mutating request, so
 * a stale/forged claim here can hide buttons but never bypass server-side authorization.
 */
export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const payload = token.split(".")[1];
    const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

export function getIsAdminFromToken(token: string | null): boolean {
  if (!token) return false;
  return !!decodeJwtPayload(token)?.isAdmin;
}
