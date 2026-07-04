import mongoose from "mongoose";

/**
 * Phase 12 (DevSecOps/Supply Chain): one doc per scan run, persisting the 5 component scores +
 * weighted overall score - same "persisted trend snapshot" reasoning as Phase 11's
 * SecurityScoreSnapshot.js (current-state posture scores aren't naturally time-series).
 */
const devSecOpsScoreSnapshotSchema = new mongoose.Schema(
  {
    repositoryScore: { type: Number, default: 100 },
    dependencyScore: { type: Number, default: 100 },
    secretScore: { type: Number, default: 100 },
    containerScore: { type: Number, default: 100 },
    pipelineScore: { type: Number, default: 100 },
    overallScore: { type: Number, default: 100 },
    scannedAt: { type: Date, default: Date.now }
  },
  { timestamps: true }
);

devSecOpsScoreSnapshotSchema.index({ scannedAt: -1 });

export default mongoose.model("DevSecOpsScoreSnapshot", devSecOpsScoreSnapshotSchema);
