import mongoose from "mongoose";

/**
 * Phase 12 (DevSecOps/Supply Chain): a generated Software Bill of Materials. `content` stores the
 * document itself (small enough to inline, same choice ComplianceReport.js makes for its summary)
 * so it can be re-served without regenerating it.
 */
const sbomDocumentSchema = new mongoose.Schema(
  {
    format: { type: String, enum: ["CycloneDX", "SPDX"], required: true },
    serialization: { type: String, enum: ["JSON", "XML"], required: true },
    componentCount: { type: Number, default: 0 },
    generatedAt: { type: Date, default: Date.now },
    generatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    content: mongoose.Schema.Types.Mixed,
    filename: { type: String, required: true }
  },
  { timestamps: true }
);

sbomDocumentSchema.index({ createdAt: -1 });

export default mongoose.model("SBOMDocument", sbomDocumentSchema);
