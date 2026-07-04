import mongoose from "mongoose";

/**
 * Phase 10 (Compliance & Governance): a piece of evidence collected by
 * services/compliance/evidenceCollector.js from an existing security subsystem and (optionally)
 * linked to the control it supports. `sourceRef` is intentionally Mixed - it may hold an ObjectId,
 * a count, or a small descriptive object depending on `sourceType`, never raw file content.
 */
const complianceEvidenceSchema = new mongoose.Schema(
  {
    sourceType: {
      type: String,
      required: true,
      enum: [
        "AUDIT_LOG", "SIEM", "THREAT_INTEL", "SOAR", "IDENTITY",
        "FILE_METADATA", "SECURITY_EVENT", "INCIDENT", "POLICY"
      ]
    },
    sourceRef: mongoose.Schema.Types.Mixed,
    summary: { type: String, required: true },
    collectedAt: { type: Date, default: Date.now },
    control: { type: mongoose.Schema.Types.ObjectId, ref: "ComplianceControl", default: null },
    approved: { type: Boolean, default: false },
    approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null }
  },
  { timestamps: true }
);

complianceEvidenceSchema.index({ control: 1, collectedAt: -1 });
complianceEvidenceSchema.index({ sourceType: 1, collectedAt: -1 });

export default mongoose.model("ComplianceEvidence", complianceEvidenceSchema);
