import mongoose from "mongoose";

/**
 * Phase 7: the result of enriching a file/scan with Threat Intelligence - the layer that sits
 * after malware scanning (ThreatScan) and DLP (DLPScan) and before the SIEM event is emitted, per
 * backend/services/threatIntel/threatIntelIntegration.js. One document per enriched file.
 *
 * Enrichment runs against data already produced by earlier scans (file hashes from ThreatScan,
 * any raw text a caller explicitly submits via POST /api/threat-intel/scan-text) rather than
 * re-reading plaintext file bytes - by the time enrichment runs (after upload), the server no
 * longer holds the plaintext (zero-knowledge encryption), so this never violates that guarantee.
 */
const threatIntelScanSchema = new mongoose.Schema(
  {
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    fileId: { type: mongoose.Schema.Types.ObjectId, ref: "File", default: null },
    threatScanId: { type: mongoose.Schema.Types.ObjectId, ref: "ThreatScan", default: null },
    dlpScanId: { type: mongoose.Schema.Types.ObjectId, ref: "DLPScan", default: null },

    originalFilename: String,

    iocMatches: [
      {
        type: { type: String },
        value: String,
        confidence: Number,
        severity: String,
        source: String,
        description: String
      }
    ],

    mitreMapping: [
      {
        techniqueId: String,
        name: String,
        tactic: String
      }
    ],

    yaraMatches: [
      {
        ruleName: String,
        severity: String,
        mitreTechniques: { type: [String], default: [] }
      }
    ],

    threatSources: { type: [String], default: [] }, // providers/sources that returned data (incl. "local")
    providerErrors: { type: [String], default: [] }, // provider names that failed/errored, non-fatal

    threatScore: { type: Number, min: 0, max: 100, default: 0 },
    threatConfidence: { type: Number, min: 0, max: 100, default: 0 },
    severity: { type: String, enum: ["None", "Low", "Medium", "High", "Critical"], default: "None" },

    scanStatus: { type: String, enum: ["pending", "completed", "failed"], default: "pending" },
    enrichedAt: { type: Date, default: Date.now }
  },
  { timestamps: true }
);

threatIntelScanSchema.index({ owner: 1, createdAt: -1 });
threatIntelScanSchema.index({ fileId: 1 });

export default mongoose.model("ThreatIntelScan", threatIntelScanSchema);
