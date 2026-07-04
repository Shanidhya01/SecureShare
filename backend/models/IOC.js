import mongoose from "mongoose";

/**
 * Phase 7 (Threat Intelligence): a single Indicator of Compromise, either learned locally
 * (e.g. promoted from a confirmed malicious ThreatIntelScan match) or seeded from an external
 * feed. This is the fast, offline-first lookup path consulted by
 * backend/services/threatIntel/iocLookupService.js before any external provider is queried -
 * providers are optional/best-effort (see providers/index.js), this collection never depends on
 * network access.
 */
const iocSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      enum: ["ip", "domain", "url", "sha256", "sha1", "md5", "email", "filename", "cert_fingerprint"],
      required: true
    },
    value: { type: String, required: true, trim: true },

    confidence: { type: Number, min: 0, max: 100, default: 50 },
    severity: { type: String, enum: ["Low", "Medium", "High", "Critical"], default: "Medium" },

    source: { type: String, default: "local" }, // e.g. "VirusTotal", "AbuseIPDB", "local"
    description: String,

    firstSeen: { type: Date, default: Date.now },
    lastSeen: { type: Date, default: Date.now },

    tags: { type: [String], default: [] },
    references: { type: [String], default: [] },

    status: { type: String, enum: ["active", "inactive"], default: "active" }
  },
  { timestamps: true }
);

iocSchema.index({ type: 1, value: 1 }, { unique: true });
iocSchema.index({ status: 1, severity: 1 });

export default mongoose.model("IOC", iocSchema);
