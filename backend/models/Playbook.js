import mongoose from "mongoose";

/**
 * Phase 8 (SOAR): a named, reusable ordered list of response actions, referenced by one or more
 * AutomationRule docs via `playbookId`. Kept separate from AutomationRule so the same response
 * procedure (e.g. "Malware Response") can be triggered by multiple rules/conditions without
 * duplicating its steps.
 */
const stepSchema = new mongoose.Schema(
  {
    type: { type: String, required: true },
    params: { type: mongoose.Schema.Types.Mixed, default: {} },
    continueOnFailure: { type: Boolean, default: true }
  },
  { _id: false }
);

const playbookSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, unique: true },
    description: String,
    category: { type: String, default: "General" }, // e.g. "Malware Response", "DLP Response"
    steps: { type: [stepSchema], default: [] },
    enabled: { type: Boolean, default: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null }
  },
  { timestamps: true }
);

export default mongoose.model("Playbook", playbookSchema);
