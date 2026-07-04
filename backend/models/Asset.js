import mongoose from "mongoose";

/**
 * Phase 11 (CSPM/ASM): a discovered piece of SecureShare's own deployment surface - not a
 * multi-cloud resource, since this project has no AWS/GCP/Azure footprint to enumerate. Populated
 * by services/cloud/assetDiscovery.js and kept fresh by the daily/manual scan orchestrator.
 */
const assetSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    type: {
      type: String,
      required: true,
      enum: [
        "Server", "Container", "DockerImage", "Volume", "Database", "Redis", "Storage",
        "APIEndpoint", "Domain", "Subdomain", "Certificate", "Service", "ReverseProxy", "Network"
      ]
    },
    environment: { type: String, enum: ["development", "staging", "production"], default: "production" },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    status: { type: String, enum: ["active", "inactive", "decommissioned"], default: "active" },
    riskScore: { type: Number, default: 0, min: 0, max: 100 },
    criticality: { type: String, enum: ["low", "medium", "high", "critical"], default: "medium" },
    tags: { type: [String], default: [] },
    metadata: mongoose.Schema.Types.Mixed,
    lastScan: Date
  },
  { timestamps: true }
);

assetSchema.index({ type: 1, status: 1 });
assetSchema.index({ name: 1, type: 1 }, { unique: true });

export default mongoose.model("Asset", assetSchema);
