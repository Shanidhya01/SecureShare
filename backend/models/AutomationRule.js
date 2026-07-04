import mongoose from "mongoose";

/**
 * Phase 8 (SOAR): a configurable automation rule watched by
 * backend/services/soar/soarEngine.js against every SecurityEvent as it's logged. A rule either
 * carries its own inline `actions` list, or points at a shared, reusable `playbookId` - exactly
 * one of the two should be set (enforced at the controller layer, not the schema, to keep this
 * flexible for manual document edits).
 */
const conditionSchema = new mongoose.Schema(
  {
    field: { type: String, required: true },   // e.g. "severity", "metadata.matchCount"
    operator: { type: String, enum: ["eq", "neq", "gt", "gte", "lt", "lte", "contains", "in"], required: true },
    value: mongoose.Schema.Types.Mixed
  },
  { _id: false }
);

const inlineActionSchema = new mongoose.Schema(
  {
    type: { type: String, required: true },
    params: { type: mongoose.Schema.Types.Mixed, default: {} },
    continueOnFailure: { type: Boolean, default: true }
  },
  { _id: false }
);

const automationRuleSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    description: String,
    enabled: { type: Boolean, default: true },

    trigger: {
      type: String,
      required: true,
      enum: [
        "THREAT_FOUND", "IOC_MATCH", "DLP_BLOCK", "SIGNATURE_FAILED", "SESSION_COMPROMISED",
        "NEW_DEVICE", "MULTIPLE_FAILED_LOGINS", "YARA_MATCH", "MITRE_CRITICAL",
        // Phase 9.5: Adaptive Authentication
        "IMPOSSIBLE_TRAVEL", "CRITICAL_RISK_LOGIN",
        // Phase 10: Compliance & Governance
        "COMPLIANCE_SCORE_DROP",
        // Phase 11: CSPM / Attack Surface Management
        "PUBLIC_EXPOSURE_CRITICAL", "CERTIFICATE_EXPIRED", "CLOUD_SCORE_DROP"
      ]
    },
    conditions: { type: [conditionSchema], default: [] },

    actions: { type: [inlineActionSchema], default: [] },
    playbookId: { type: mongoose.Schema.Types.ObjectId, ref: "Playbook", default: null },

    priority: { type: Number, default: 100 }, // lower runs first

    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null }
  },
  { timestamps: true }
);

automationRuleSchema.index({ enabled: 1, trigger: 1, priority: 1 });

export default mongoose.model("AutomationRule", automationRuleSchema);
