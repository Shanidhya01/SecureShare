import mongoose from "mongoose";

/**
 * Phase 11 (CSPM/ASM): unified finding store for Configuration Scanner (PART 3), Attack Surface
 * Management (PART 5), and Threat Intelligence correlation (PART 14) results - one schema instead
 * of three near-identical collections, distinguished by `category`.
 */
const cloudFindingSchema = new mongoose.Schema(
  {
    asset: { type: mongoose.Schema.Types.ObjectId, ref: "Asset" },
    category: { type: String, required: true, enum: ["CONFIGURATION", "EXPOSURE", "CERTIFICATE", "THREAT_INTEL"] },
    ruleId: { type: String, required: true },
    title: { type: String, required: true },
    severity: { type: String, enum: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], default: "MEDIUM" },
    status: { type: String, enum: ["open", "acknowledged", "resolved"], default: "open" },
    recommendation: String,
    reference: String,
    detectedAt: { type: Date, default: Date.now },
    resolvedAt: Date,
    metadata: mongoose.Schema.Types.Mixed
  },
  { timestamps: true }
);

cloudFindingSchema.index({ category: 1, status: 1, severity: 1 });
cloudFindingSchema.index({ ruleId: 1, asset: 1, status: 1 });

export default mongoose.model("CloudFinding", cloudFindingSchema);
