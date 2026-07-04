import mongoose from "mongoose";

/**
 * Phase 9 (IAM): a WebAuthn credential registered by a user, verified/consulted via
 * @simplewebauthn/server in backend/controllers/passkey.controller.js. `credentialId` and
 * `publicKey` are stored base64url-encoded exactly as @simplewebauthn/server returns them.
 */
const passkeySchema = new mongoose.Schema(
  {
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    credentialId: { type: String, required: true, unique: true },
    publicKey: { type: String, required: true },
    counter: { type: Number, default: 0 },
    deviceType: String, // "singleDevice" | "multiDevice"
    backedUp: { type: Boolean, default: false },
    transports: { type: [String], default: [] },
    label: { type: String, default: "Passkey" },
    lastUsedAt: { type: Date, default: null }
  },
  { timestamps: true }
);

passkeySchema.index({ owner: 1 });

export default mongoose.model("Passkey", passkeySchema);
