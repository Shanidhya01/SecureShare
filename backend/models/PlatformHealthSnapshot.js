import mongoose from "mongoose";

/**
 * Phase 13 (Platform Operations) - PART 6: one doc per health check run, persisting per-component
 * status plus the weighted overall score - mirrors Phase 11/12's *ScoreSnapshot trend-snapshot
 * pattern (current-state health isn't naturally time-series without persisting it).
 */
const componentSchema = new mongoose.Schema(
  {
    name: String,
    status: { type: String, enum: ["UP", "DEGRADED", "DOWN", "UNKNOWN"], default: "UNKNOWN" },
    message: String,
    latencyMs: Number,
    details: mongoose.Schema.Types.Mixed
  },
  { _id: false }
);

const platformHealthSnapshotSchema = new mongoose.Schema(
  {
    overallScore: { type: Number, default: 100 },
    overallStatus: { type: String, enum: ["HEALTHY", "WARNING", "CRITICAL"], default: "HEALTHY" },
    components: [componentSchema],
    checkedAt: { type: Date, default: Date.now }
  },
  { timestamps: true }
);

platformHealthSnapshotSchema.index({ checkedAt: -1 });

export default mongoose.model("PlatformHealthSnapshot", platformHealthSnapshotSchema);
