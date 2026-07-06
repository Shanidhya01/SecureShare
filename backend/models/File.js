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
  // v1 only: sha256 fingerprint (hex) of the DER-encoded RSA public key used to wrap encryptedKey,
  // so downloadFileV1 can detect - and clearly report - a server RSA keypair mismatch (e.g. after a
  // key rotation or a multi-instance deploy with divergent keys/*.pem) instead of a generic decrypt
  // failure. Absent on files uploaded before this check existed; those skip the check.
  rsaKeyFingerprint: String,

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

  // Phase 4: malware/threat scan result, mirrored from the ThreatScan doc referenced by scanId
  // at upload time. Absent/"not_scanned" on every file uploaded before Phase 4 - those remain
  // downloadable exactly as before (quarantined defaults to false, never blocks them).
  scanId: { type: mongoose.Schema.Types.ObjectId, ref: "ThreatScan", default: null },
  scanStatus: { type: String, enum: ["not_scanned", "pending", "completed", "failed"], default: "not_scanned" },
  riskLevel: { type: String, enum: ["Low", "Medium", "High", "Critical"], default: null },
  quarantined: { type: Boolean, default: false },

  // Phase 5: DLP scan result, mirrored from the DLPScan doc referenced by dlpScanId at upload
  // time - same denormalization pattern as the Phase 4 fields above. Absent/"not_scanned" on
  // every file uploaded before Phase 5, which remain downloadable exactly as before.
  dlpScanId: { type: mongoose.Schema.Types.ObjectId, ref: "DLPScan", default: null },
  dlpStatus: { type: String, enum: ["not_scanned", "pending", "completed", "failed", "skipped"], default: "not_scanned" },
  dlpRisk: { type: String, enum: ["None", "Low", "Medium", "High", "Critical"], default: null },
  dlpDecision: { type: String, enum: ["allow", "warn", "require_approval", "block"], default: null },

  // Phase 7: Threat Intelligence enrichment result, mirrored from the ThreatIntelScan doc
  // referenced by threatIntelScanId once background enrichment completes (see
  // backend/services/threatIntel/threatIntelIntegration.js). Absent/defaults on every file
  // uploaded before Phase 7 or while enrichment is still running - never blocks access.
  threatIntelScanId: { type: mongoose.Schema.Types.ObjectId, ref: "ThreatIntelScan", default: null },
  threatScore: { type: Number, default: 0 },
  threatConfidence: { type: Number, default: 0 },
  iocMatchCount: { type: Number, default: 0 },

  // Phase 3: Zero Trust access policy. Every field is optional/empty by default, so files with
  // no policy configured behave exactly as before (backend/services/policyEngine.js treats an
  // all-empty policy as "no restrictions, allow"). Evaluated on every download attempt.
  policy: {
    allowedCountries: { type: [String], default: [] },  // ISO country codes; empty = unrestricted
    allowedIPs: { type: [String], default: [] },         // empty = unrestricted
    allowedDevices: { type: [String], default: [] },     // device fingerprint hashes; empty = unrestricted
    businessHours: {
      enabled: { type: Boolean, default: false },
      startHour: { type: Number, default: 0 },  // UTC hour, 0-23
      endHour: { type: Number, default: 24 }    // UTC hour, 0-24 (24 = midnight end-of-day)
    },
    maxDevices: { type: Number, default: 0 },     // 0 = unlimited distinct devices
    requireApproval: { type: Boolean, default: false } // require an authenticated, trusted-device recipient
  },

  // Download logs: who, from where, and when - extended in Phase 3 with device/policy context,
  // and in Phase 4 with a snapshot of the file's scan result at download time.
  // Populated for both allowed and denied attempts (decision/denialReason distinguish them).
  logs: [{
    ip: String,
    userEmail: String,
    time: Date,
    deviceId: String,
    browser: String,
    operatingSystem: String,
    country: String,
    decision: { type: String, enum: ["allow", "deny"] },
    denialReason: String,
    scanStatus: String,
    riskLevel: String
  }]
}, { timestamps: true });

export default mongoose.model("File", fileSchema);
