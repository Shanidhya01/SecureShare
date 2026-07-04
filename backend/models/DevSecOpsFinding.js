import mongoose from "mongoose";

/**
 * Phase 12 (DevSecOps/Supply Chain): unified finding store for the Dependency, Secret, SAST,
 * Container, IaC, and Pipeline scanners - one schema instead of six near-identical collections,
 * distinguished by `category`, mirroring Phase 11's CloudFinding.js.
 */
const devSecOpsFindingSchema = new mongoose.Schema(
  {
    repository: { type: mongoose.Schema.Types.ObjectId, ref: "Repository" },
    category: { type: String, required: true, enum: ["DEPENDENCY", "SECRET", "SAST", "CONTAINER", "IAC", "PIPELINE"] },
    ruleId: { type: String, required: true },
    title: { type: String, required: true },
    severity: { type: String, enum: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], default: "MEDIUM" },
    status: { type: String, enum: ["open", "acknowledged", "resolved"], default: "open" },

    file: String,
    line: Number,
    package: String,
    currentVersion: String,
    recommendedVersion: String,

    recommendation: String,
    reference: String,
    detectedAt: { type: Date, default: Date.now },
    resolvedAt: Date,
    metadata: mongoose.Schema.Types.Mixed
  },
  { timestamps: true }
);

devSecOpsFindingSchema.index({ category: 1, status: 1, severity: 1 });
devSecOpsFindingSchema.index({ ruleId: 1, file: 1, package: 1, status: 1 });

export default mongoose.model("DevSecOpsFinding", devSecOpsFindingSchema);
