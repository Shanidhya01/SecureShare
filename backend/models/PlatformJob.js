import mongoose from "mongoose";

/**
 * Phase 13 (Platform Operations) - PART 5: one doc per background job execution (queued via
 * services/platform/queue.js, BullMQ-backed with an in-process fallback). Persists status/
 * duration/retryCount/logs per spec Part 5, independent of whether BullMQ/Redis is available.
 */
const platformJobSchema = new mongoose.Schema(
  {
    queue: {
      type: String,
      required: true,
      enum: ["threat-scan", "malware-scan", "cloud-scan", "compliance-scan", "devsecops-scan", "report-generation", "notification", "email"]
    },
    jobId: String,
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    status: { type: String, enum: ["queued", "running", "completed", "failed", "retrying"], default: "queued" },
    payload: mongoose.Schema.Types.Mixed,
    result: mongoose.Schema.Types.Mixed,
    error: String,
    retryCount: { type: Number, default: 0 },
    maxRetries: { type: Number, default: 3 },
    durationMs: Number,
    logs: [{ at: { type: Date, default: Date.now }, message: String }],
    startedAt: Date,
    finishedAt: Date
  },
  { timestamps: true }
);

platformJobSchema.index({ queue: 1, status: 1, createdAt: -1 });

export default mongoose.model("PlatformJob", platformJobSchema);
