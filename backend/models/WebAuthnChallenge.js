import mongoose from "mongoose";

/**
 * Phase 9 (IAM): short-lived storage for a WebAuthn registration/authentication challenge,
 * bridging the "generate options" and "verify response" requests of the same ceremony.
 * `owner` is null for a login challenge issued before the user is authenticated (identified by
 * `email` instead). The TTL index removes documents 5 minutes after creation - well past any
 * realistic ceremony completion time - so abandoned challenges never accumulate.
 */
const webAuthnChallengeSchema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
  email: { type: String, default: null },
  challenge: { type: String, required: true },
  type: { type: String, enum: ["register", "login"], required: true },
  createdAt: { type: Date, default: Date.now, expires: 300 }
});

export default mongoose.model("WebAuthnChallenge", webAuthnChallengeSchema);
