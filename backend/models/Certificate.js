import mongoose from "mongoose";

/**
 * Phase 11 (CSPM/ASM): tracks a monitored TLS certificate (PART 4). `lastNotifiedTier` dedupes
 * repeat SIEM alerts across the 30/15/7/expired thresholds - each tier logs at most once until the
 * certificate is renewed and the tier resets.
 */
const certificateSchema = new mongoose.Schema(
  {
    domain: { type: String, required: true, unique: true },
    asset: { type: mongoose.Schema.Types.ObjectId, ref: "Asset" },
    issuer: String,
    subject: String,
    validFrom: Date,
    validTo: Date,
    algorithm: String,
    tlsVersion: String,
    cipher: String,
    status: { type: String, enum: ["valid", "expiring", "expired", "unreachable"], default: "valid" },
    daysRemaining: Number,
    lastNotifiedTier: { type: String, enum: ["none", "30", "15", "7", "expired"], default: "none" },
    lastCheckedAt: Date
  },
  { timestamps: true }
);

export default mongoose.model("Certificate", certificateSchema);
