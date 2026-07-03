import mongoose from "mongoose";

/**
 * A record of a pre-encryption Data Loss Prevention scan (Phase 5). Created by POST /api/dlp/scan
 * BEFORE the file is encrypted client-side, for the same reason Phase 4's ThreatScan is - this is
 * one of the few deliberate, documented moments the server sees plaintext bytes (see
 * backend/controllers/dlp.controller.js), and it never persists them: the scan runs against an
 * in-memory buffer for the lifetime of the request only. Only masked previews of any sensitive
 * matches are stored (see backend/services/dlp/maskUtils.js) - never the raw secret values.
 *
 * `fileId` starts null (no File document exists yet at scan time) and is linked once the caller
 * completes the actual encrypted upload referencing this scan's id - see uploadFileV2 in
 * file.controller.js. `consumedByUpload` prevents a single scan result from being replayed
 * across multiple uploads, same as ThreatScan.
 */
const dlpScanSchema = new mongoose.Schema(
  {
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    fileId: { type: mongoose.Schema.Types.ObjectId, ref: "File", default: null },

    originalFilename: String,
    fileSizeBytes: Number,

    // False for binary/unsupported files - those are skipped gracefully rather than scanned.
    supported: { type: Boolean, default: true },
    skipReason: String,
    truncated: { type: Boolean, default: false }, // true if the file exceeded MAX_SCAN_BYTES

    findings: [
      {
        detectorId: String, // e.g. "aws_access_key", matches services/dlp/detectors/*.js `id`
        label: String,
        category: String,
        severity: { type: String, enum: ["Low", "Medium", "High", "Critical"] },
        count: Number,
        samples: { type: [String], default: [] } // masked previews only, never raw values
      }
    ],
    matchedPatterns: { type: [String], default: [] }, // detector ids that matched, for quick filtering

    severity: { type: String, enum: ["None", "Low", "Medium", "High", "Critical"], default: "None" },

    // Snapshot of the policy config applied at scan time (services/dlp/dlpPolicyConfig.js),
    // kept for audit purposes even if the live config is tuned later.
    policy: { type: mongoose.Schema.Types.Mixed, default: {} },

    decision: { type: String, enum: ["allow", "warn", "require_approval", "block"], default: "allow" },
    scanStatus: { type: String, enum: ["pending", "completed", "failed"], default: "pending" },

    // Owner override for a "require_approval" decision - set via POST /api/dlp/scans/:id/acknowledge.
    // Does not change `decision` itself (kept as an audit trail of what was originally found).
    acknowledged: { type: Boolean, default: false },
    acknowledgedAt: Date,

    consumedByUpload: { type: Boolean, default: false }
  },
  { timestamps: true }
);

dlpScanSchema.index({ owner: 1, createdAt: -1 });

export default mongoose.model("DLPScan", dlpScanSchema);
