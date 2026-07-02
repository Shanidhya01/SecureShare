import mongoose from "mongoose";

const fileSchema = new mongoose.Schema({
  filename: String,
  cloudinaryId: String,

  // encryptionVersion 1 = legacy server-side AES-256-CBC (global RSA keypair).
  // encryptionVersion 2 = client-side E2E AES-256-GCM (Web Crypto API, zero-knowledge).
  encryptionVersion: { type: Number, default: 1 },
  mimeType: String,
  originalFilename: String,         // v2: original file name, kept distinct from `filename` for clarity/crypto-agility
  algorithm: String,                // v2: e.g. "AES-256-GCM", recorded for future crypto-agility

  // v1 fields: encryptedKey = AES key RSA-wrapped with the server's global keypair; iv = 16-byte CBC IV.
  encryptedKey: String,
  // v1: base64 16-byte CBC IV. v2: base64 12-byte (96-bit) GCM IV. Never both on the same doc.
  iv: String,

  // v2 fields: AES key wrapped client-side, server never sees the raw key.
  wrappedOwnerKey: String,          // AES key wrapped with the uploader's own RSA-OAEP-SHA256 public key
  wrappedPasswordKey: String,       // AES key wrapped with a PBKDF2(password)-derived key, only if a share password was set
  keySalt: String,                  // base64 PBKDF2 salt for wrappedPasswordKey
  keyIterations: { type: Number, default: 210000 },
  passwordKeyIvHint: String,        // base64 IV used for the AES-GCM wrap of wrappedPasswordKey itself

  // Phase 2: digital signature over the encrypted file, for integrity/authenticity verification.
  // Optional - absent on legacy (v1) and pre-Phase-2 (v2) files, which remain downloadable unsigned.
  signature: String,                // base64 ECDSA signature, computed over the ciphertext bytes
  fileHash: String,                 // base64 SHA-256 hash of the ciphertext, informational (recomputed client-side for verification, never trusted from the server)
  hashAlgorithm: String,            // e.g. "SHA-256"
  signatureAlgorithm: String,       // e.g. "ECDSA-P256-SHA256"
  signedAt: Date,

  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User" },

  passwordHash: String,
  oneTime: Boolean,
  maxDownloads: { type: Number, default: 1 },
  revoked: { type: Boolean, default: false },

  expiresAt: Date,
  downloadCount: { type: Number, default: 0 },

  // Download logs: who, from where, and when
  logs: [{ ip: String, userEmail: String, time: Date }]
}, { timestamps: true });

export default mongoose.model("File", fileSchema);
