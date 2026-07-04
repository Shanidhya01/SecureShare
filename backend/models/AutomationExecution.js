import mongoose from "mongoose";

/**
 * Phase 8 (SOAR): a full audit record of one automation rule firing - which playbook ran, every
 * action's individual outcome, overall status/duration, and the incident (if any) it updated.
 * This is the "Action History" the SOAR dashboard's Recent/Failed Executions sections read from.
 */
const actionResultSchema = new mongoose.Schema(
  {
    type: String,
    params: mongoose.Schema.Types.Mixed,
    success: Boolean,
    detail: String,
    durationMs: Number
  },
  { _id: false }
);

const automationExecutionSchema = new mongoose.Schema(
  {
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    rule: { type: mongoose.Schema.Types.ObjectId, ref: "AutomationRule", required: true },
    ruleName: String, // snapshot, survives rule deletion
    playbook: { type: mongoose.Schema.Types.ObjectId, ref: "Playbook", default: null },
    playbookName: String,

    triggerEvent: { type: mongoose.Schema.Types.ObjectId, ref: "SecurityEvent", default: null },
    trigger: String, // the AutomationRule.trigger value that fired

    actionsExecuted: { type: [actionResultSchema], default: [] },

    status: { type: String, enum: ["completed", "partial", "failed"], default: "completed" },
    durationMs: { type: Number, default: 0 },
    result: String, // short human-readable summary

    incident: { type: mongoose.Schema.Types.ObjectId, ref: "Incident", default: null }
  },
  { timestamps: true }
);

automationExecutionSchema.index({ owner: 1, createdAt: -1 });
automationExecutionSchema.index({ rule: 1, createdAt: -1 });
automationExecutionSchema.index({ status: 1, createdAt: -1 });

export default mongoose.model("AutomationExecution", automationExecutionSchema);
