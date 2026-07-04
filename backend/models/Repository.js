import mongoose from "mongoose";

/**
 * Phase 12 (DevSecOps/Supply Chain): SecureShare has no multi-repo GitHub org to enumerate, so
 * this is a self-scan of the repository this code actually lives in - populated by
 * services/devsecops/repositoryScanner.js from real, read-only `git` commands, not a live GitHub/
 * GitLab/Azure DevOps/Bitbucket API integration.
 */
const repositorySchema = new mongoose.Schema(
  {
    name: { type: String, required: true, unique: true },
    provider: { type: String, enum: ["GitHub", "GitLab", "AzureDevOps", "Bitbucket", "Unknown"], default: "Unknown" },
    remoteUrl: String,
    defaultBranch: { type: String, default: "main" },
    branch: String,
    commit: String,
    ownerName: String,
    visibility: { type: String, enum: ["public", "private", "unknown"], default: "unknown" },
    riskScore: { type: Number, default: 0, min: 0, max: 100 },
    lastScan: Date
  },
  { timestamps: true }
);

export default mongoose.model("Repository", repositorySchema);
