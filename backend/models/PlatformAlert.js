import mongoose from "mongoose";

/**
 * Phase 13 (Platform Operations) - PART 10: fired alert-rule instances from
 * services/platform/alertEngine.js. Each alert also emits a SIEM event (which auto-triggers SOAR),
 * but this collection is the queryable "Alerts" list for the /platform dashboard, deduplicated by
 * `rule` while `active`.
 */
const platformAlertSchema = new mongoose.Schema(
  {
    rule: { type: String, required: true },
    severity: { type: String, enum: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], default: "MEDIUM" },
    message: String,
    active: { type: Boolean, default: true },
    metadata: mongoose.Schema.Types.Mixed,
    triggeredAt: { type: Date, default: Date.now },
    resolvedAt: Date
  },
  { timestamps: true }
);

platformAlertSchema.index({ rule: 1, active: 1 });
platformAlertSchema.index({ triggeredAt: -1 });

export default mongoose.model("PlatformAlert", platformAlertSchema);
