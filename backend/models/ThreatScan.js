import mongoose from "mongoose";

/**
 * A record of a pre-encryption malware/threat scan (Phase 4). Created by POST /api/threats/scan
 * BEFORE the file is encrypted client-side - this is the one deliberate, documented moment the
 * server sees plaintext bytes (see backend/controllers/threat.controller.js), and it never
 * persists them: the scan runs against an in-memory buffer for the lifetime of the request only.
 *
 * `fileId` starts null (no File document exists yet at scan time) and is linked once the caller
 * completes the actual encrypted upload referencing this scan's id - see uploadFileV2/uploadFileV1
 * in file.controller.js. `consumedByUpload` prevents a single clean scan result from being replayed
 * across multiple uploads.
 */
const threatScanSchema = new mongoose.Schema(
  {
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    fileId: { type: mongoose.Schema.Types.ObjectId, ref: "File", default: null },

    originalFilename: String,
    fileSizeBytes: Number,

    claimedMimeType: String,   // what the browser/client claimed (File.type)
    detectedMimeType: String,  // what magic-byte inspection actually found
    mimeMismatch: { type: Boolean, default: false },
    extension: String,
    dangerousExtension: { type: Boolean, default: false },   // claimed filename ends in a dangerous extension
    dangerousDetectedType: { type: Boolean, default: false }, // magic-byte content IS executable, regardless of claimed name (disguise detection)
    hasMacros: { type: Boolean, default: false },
    isEncryptedArchive: { type: Boolean, default: false },
    magicBytesHex: String, // first bytes of the file, hex-encoded, for display/audit only

    hashes: {
      sha256: String,
      sha1: String,
      md5: String
    },

    clamav: {
      status: { type: String, enum: ["clean", "infected", "error", "unavailable"], default: "unavailable" },
      engineVersion: String,
      scannedAt: Date,
      threatNames: { type: [String], default: [] }
    },

    virusTotal: {
      status: {
        type: String,
        enum: ["skipped", "clean", "suspicious", "malicious", "unknown", "error"],
        default: "skipped"
      },
      maliciousCount: { type: Number, default: 0 },
      suspiciousCount: { type: Number, default: 0 },
      totalEngines: { type: Number, default: 0 },
      threatNames: { type: [String], default: [] },
      checkedAt: Date
    },

    riskLevel: { type: String, enum: ["Low", "Medium", "High", "Critical"], default: "Low" },
    quarantined: { type: Boolean, default: false },
    scanStatus: { type: String, enum: ["pending", "completed", "failed"], default: "pending" },

    consumedByUpload: { type: Boolean, default: false }
  },
  { timestamps: true }
);

threatScanSchema.index({ owner: 1, createdAt: -1 });

export default mongoose.model("ThreatScan", threatScanSchema);
