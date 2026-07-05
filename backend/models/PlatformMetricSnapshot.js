import mongoose from "mongoose";

/**
 * Phase 13 (Platform Operations) - PART 2: periodic snapshot of the in-memory metrics collected by
 * services/platform/metricsCollector.js, so latency/scan-duration/auth/scan-activity history
 * survives process restarts and can be charted over time on the /platform dashboard. No host
 * resource fields (CPU/memory/disk) - this deployment has no VM to monitor those on.
 */
const durationStatSchema = new mongoose.Schema({ count: Number, avgMs: Number, p95Ms: Number }, { _id: false });

const platformMetricSnapshotSchema = new mongoose.Schema(
  {
    api: {
      requestCount: Number,
      avgLatencyMs: Number,
      p95LatencyMs: Number,
      p99LatencyMs: Number,
      errorCount: Number,
      errorRate: Number
    },
    uploadDownload: {
      upload: { count: Number, avgMs: Number, p95Ms: Number },
      download: { count: Number, avgMs: Number, p95Ms: Number }
    },
    scanDurations: {
      threatScan: durationStatSchema,
      malwareScan: durationStatSchema,
      dlpScan: durationStatSchema,
      complianceScan: durationStatSchema,
      soarExecution: durationStatSchema,
      cloudScan: durationStatSchema,
      devSecOpsScan: durationStatSchema,
      reportGeneration: durationStatSchema
    },
    auth: {
      successCount: Number,
      failureCount: Number,
      successRate: Number,
      failureRate: Number
    },
    scanActivity: {
      threatScans: Number,
      dlpScans: Number,
      soarExecutions: Number,
      complianceScans: Number,
      cloudScans: Number,
      devSecOpsScans: Number
    },
    queueLength: Number,
    recordedAt: { type: Date, default: Date.now }
  },
  { timestamps: true }
);

platformMetricSnapshotSchema.index({ recordedAt: -1 });

export default mongoose.model("PlatformMetricSnapshot", platformMetricSnapshotSchema);
