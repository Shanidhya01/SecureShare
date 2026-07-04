import mongoose from "mongoose";

/**
 * Phase 12 (DevSecOps/Supply Chain): a CI/CD pipeline observation. `source: "detected"` means it
 * was inferred from repo config (e.g. "no .github/workflows found"); `source: "live"` means it was
 * fetched from a real CI provider API (only happens if GITHUB_TOKEN/GITHUB_REPO are configured -
 * see services/devsecops/pipelineMonitor.js). Never synthesized/fake data either way.
 */
const pipelineRunSchema = new mongoose.Schema(
  {
    provider: { type: String, enum: ["GitHubActions", "GitLabCI", "Jenkins", "AzureDevOps", "None"], default: "None" },
    name: { type: String, required: true },
    status: { type: String, enum: ["success", "failed", "blocked", "unknown"], default: "unknown" },
    branch: String,
    commit: String,
    testCoveragePercent: Number,
    securityGatePassed: { type: Boolean, default: null },
    startedAt: Date,
    finishedAt: Date,
    source: { type: String, enum: ["detected", "live"], default: "detected" }
  },
  { timestamps: true }
);

pipelineRunSchema.index({ createdAt: -1 });

export default mongoose.model("PipelineRun", pipelineRunSchema);
