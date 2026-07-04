import mongoose from "mongoose";

/**
 * Phase 10 (Compliance & Governance): the result of evaluating one ComplianceControl during a
 * services/compliance/complianceEngine.js `runAssessment()` run. Every run writes a fresh row
 * (history is kept, not overwritten) so the dashboard/trend charts can show compliance over time.
 */
const complianceAssessmentSchema = new mongoose.Schema(
  {
    control: { type: mongoose.Schema.Types.ObjectId, ref: "ComplianceControl", required: true },
    framework: { type: mongoose.Schema.Types.ObjectId, ref: "ComplianceFramework", required: true },
    status: { type: String, enum: ["PASS", "FAIL", "PARTIAL", "NOT_APPLICABLE"], required: true },
    score: { type: Number, min: 0, max: 100, required: true },
    evidenceRefs: [{ type: mongoose.Schema.Types.ObjectId, ref: "ComplianceEvidence" }],
    details: mongoose.Schema.Types.Mixed,
    recommendations: { type: [String], default: [] },
    evaluatedAt: { type: Date, default: Date.now }
  },
  { timestamps: true }
);

complianceAssessmentSchema.index({ control: 1, evaluatedAt: -1 });
complianceAssessmentSchema.index({ framework: 1, evaluatedAt: -1 });
complianceAssessmentSchema.index({ status: 1, evaluatedAt: -1 });

export default mongoose.model("ComplianceAssessment", complianceAssessmentSchema);
