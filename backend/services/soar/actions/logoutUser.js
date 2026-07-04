/**
 * Phase 8 (SOAR) action: revokes every active session for the triggering event's owner - a
 * full logout, distinct from revokeSession's narrower single/targeted revocation.
 */
import Session from "../../../models/Session.js";

export default async function logoutUser(params, event) {
  const result = await Session.updateMany({ owner: event.owner, revoked: false }, { revoked: true });
  return { success: true, detail: `Logged out user - revoked ${result.modifiedCount} session(s)` };
}
