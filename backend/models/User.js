import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,

  // base64 SPKI DER, RSA-OAEP-SHA256 public key generated client-side for zero-knowledge E2E encryption.
  // The matching private key never leaves the browser (see frontend/lib/crypto/keyStorage.ts).
  publicKey: String,

  // base64 SPKI DER, ECDSA P-256 public signing key generated client-side (Phase 2: integrity/
  // authenticity verification). The matching private signing key never leaves the browser either.
  signingPublicKey: String,

  // Phase 8 (SOAR): the first admin concept in this codebase. Defaults to false for every
  // existing/new account - grant manually (e.g. directly in Mongo) to allow managing automation
  // rules/playbooks. Never settable via any public API.
  isAdmin: { type: Boolean, default: false }
});

export default mongoose.model("User", userSchema);
