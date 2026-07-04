import mongoose from "mongoose";

/**
 * Phase 7: a stored detection rule consulted by backend/services/threatIntel/yaraEngine.js.
 * `ruleSource` holds the rule text in a documented, simplified YARA-like syntax (string/regex
 * "strings:" section + a boolean "condition:" over them) - see yaraEngine.js's header comment for
 * why full native YARA isn't used here. Kept in Mongo (not flat files) so rules can be managed
 * without a redeploy, consistent with how DLP's policy is code-configured but IOC data is DB-backed.
 */
const yaraRuleSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, unique: true },
    description: String,
    ruleSource: { type: String, required: true },
    mitreTechniques: { type: [String], default: [] }, // e.g. ["T1059", "T1027"]
    severity: { type: String, enum: ["Low", "Medium", "High", "Critical"], default: "Medium" },
    enabled: { type: Boolean, default: true }
  },
  { timestamps: true }
);

export default mongoose.model("YaraRule", yaraRuleSchema);
