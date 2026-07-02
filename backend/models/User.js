import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,

  // base64 SPKI DER, RSA-OAEP-SHA256 public key generated client-side for zero-knowledge E2E encryption.
  // The matching private key never leaves the browser (see frontend/lib/keyStore.ts).
  publicKey: String
});

export default mongoose.model("User", userSchema);
