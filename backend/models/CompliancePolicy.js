import mongoose from "mongoose";

/**
 * Phase 10 (Compliance & Governance): a versioned governance policy setting. Deliberately scoped
 * to governance-only concerns not already owned by SecurityPolicy.js (Phase 9) - MFA/session/
 * password/country settings remain on SecurityPolicy and are read from there as evidence by
 * services/compliance/evidenceCollector.js rather than duplicated here.
 *
 * Every update inserts a new document with an incremented `version` rather than mutating an
 * existing one, so the full policy history is preserved (spec requirement: "Policy Versioning").
 * The "current" value for a given `name` is the highest-versioned document with `enabled: true`.
 */
const compliancePolicySchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      enum: [
        "FILE_RETENTION_DAYS", "MAX_UPLOAD_SIZE_MB", "BLOCKED_FILE_TYPES",
        "RESTRICTED_COUNTRIES", "DLP_ENFORCEMENT"
      ]
    },
    value: mongoose.Schema.Types.Mixed,
    version: { type: Number, required: true, default: 1 },
    enabled: { type: Boolean, default: true },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },

    // Phase 10 continuation: lightweight approval trail for governance review, additive and
    // optional - a policy version is fully effective (see policyEvaluator.js's
    // getCurrentPolicyValues()) whether or not it has been reviewed.
    approvalStatus: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
    approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
    approvedAt: { type: Date, default: null }
  },
  { timestamps: true }
);

compliancePolicySchema.index({ name: 1, version: -1 }, { unique: true });

export default mongoose.model("CompliancePolicy", compliancePolicySchema);
