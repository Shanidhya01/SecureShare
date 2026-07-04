/**
 * Phase 8 (SOAR) action: revokes the session tied to the triggering event's owner (or a specific
 * session id if provided via params.sessionId), using the exact `Session.revoked` field
 * backend/middleware/auth.middleware.js already enforces.
 */
import Session from "../../../models/Session.js";

export default async function revokeSession(params, event) {
  const filter = params?.sessionId ? { sessionId: params.sessionId } : { owner: event.owner, revoked: false };
  const result = await Session.updateMany(filter, { revoked: true });

  if (result.modifiedCount === 0) return { success: false, detail: "No active session found to revoke" };
  return { success: true, detail: `Revoked ${result.modifiedCount} session(s)` };
}
