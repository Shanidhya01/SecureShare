import mongoose from "mongoose";

/**
 * Phase 10 (Compliance & Governance): an audit record of a generated compliance report. The
 * actual PDF/CSV/JSON bytes are built on-demand by services/compliance/reportGenerator.js and
 * streamed directly to the response (mirroring how SOAR/SIEM exports already work) - this
 * document only records that a report was generated, by whom, and its headline numbers.
 */
const complianceReportSchema = new mongoose.Schema(
  {
    format: { type: String, enum: ["PDF", "CSV", "JSON"], required: true },
    frameworks: { type: [String], default: [] },
    overallScore: { type: Number, min: 0, max: 100 },
    summary: mongoose.Schema.Types.Mixed,
    generatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    filename: { type: String, required: true }
  },
  { timestamps: true }
);

complianceReportSchema.index({ createdAt: -1 });

export default mongoose.model("ComplianceReport", complianceReportSchema);
