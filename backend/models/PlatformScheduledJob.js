import mongoose from "mongoose";

/**
 * Phase 13 (Platform Operations) - PART 11: registry of the node-cron schedules managed by
 * services/platform/scheduler.js (both the pre-existing Phase 10/11/12 cron jobs and the new
 * Phase 13 ones), so the Scheduler Dashboard can show last/next run, execution time, status, retry
 * count and failures, and let an admin Run Now / Pause / Resume each one.
 */
const platformScheduledJobSchema = new mongoose.Schema(
  {
    key: { type: String, required: true, unique: true },
    label: String,
    cronExpression: String,
    enabled: { type: Boolean, default: true },
    lastRunAt: Date,
    lastDurationMs: Number,
    lastStatus: { type: String, enum: ["success", "failed", "never_run"], default: "never_run" },
    lastError: String,
    nextRunAt: Date,
    retryCount: { type: Number, default: 0 },
    failureCount: { type: Number, default: 0 }
  },
  { timestamps: true }
);

export default mongoose.model("PlatformScheduledJob", platformScheduledJobSchema);
