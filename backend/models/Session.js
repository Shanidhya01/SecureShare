import mongoose from "mongoose";

/**
 * An active login session, tied to a JWT via its `sessionId` (embedded in the token as `sid`).
 * Lets users see and revoke sessions from other devices/browsers - revoking sets `revoked: true`,
 * and backend/middleware/auth.middleware.js rejects any request bearing that session's token.
 *
 * Tokens issued before this model existed have no `sid` claim; the auth middleware treats that
 * as "untracked legacy session" and skips the revocation check rather than rejecting them, so
 * existing logged-in users aren't logged out by this change.
 */
const sessionSchema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  sessionId: { type: String, required: true, unique: true },

  deviceId: String,
  browser: String,
  operatingSystem: String,
  ip: String,
  country: String,

  createdAt: { type: Date, default: Date.now },
  lastActiveAt: { type: Date, default: Date.now },
  revoked: { type: Boolean, default: false }
});

export default mongoose.model("Session", sessionSchema);
