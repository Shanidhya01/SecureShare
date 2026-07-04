import mongoose from "mongoose";

/**
 * Phase 11 (CSPM/ASM): one doc per scan run, persisting the 6 component scores + weighted overall
 * score (PART 6/PART 8's "trend history"/"Score History" chart) - current-state posture scores
 * aren't naturally time-series, so (like ComplianceAssessment backing the Compliance trend chart)
 * each scan run's result is snapshotted here rather than recomputed retroactively.
 */
const securityScoreSnapshotSchema = new mongoose.Schema(
  {
    assetScore: { type: Number, default: 100 },
    configScore: { type: Number, default: 100 },
    exposureScore: { type: Number, default: 100 },
    certScore: { type: Number, default: 100 },
    identityScore: { type: Number, default: 100 },
    complianceScore: { type: Number, default: 100 },
    overallScore: { type: Number, default: 100 },
    scannedAt: { type: Date, default: Date.now }
  },
  { timestamps: true }
);

securityScoreSnapshotSchema.index({ scannedAt: -1 });

export default mongoose.model("SecurityScoreSnapshot", securityScoreSnapshotSchema);
