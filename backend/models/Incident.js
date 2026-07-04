import mongoose from "mongoose";

/**
 * Phase 6 (SIEM): an Incident groups related SecurityEvent docs that the correlation engine
 * (services/siem/correlationEngine.js) judged to be part of the same underlying story - e.g. a
 * malware upload, its quarantine, and a subsequent blocked download. Purely a read/aggregation
 * concept - it never blocks or alters the events it groups.
 */
const incidentSchema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },

  ruleId: { type: String, required: true },
  title: { type: String, required: true },
  summary: String,

  category: {
    type: String,
    enum: ["AUTH", "ENCRYPTION", "SIGNATURE", "ZERO_TRUST", "THREAT", "DLP", "UPLOAD", "DOWNLOAD", "DEVICE", "SESSION", "AUTOMATION", "IAM"]
  },
  severity: { type: String, enum: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], default: "MEDIUM" },
  status: { type: String, enum: ["open", "investigating", "resolved"], default: "open" },

  file: { type: mongoose.Schema.Types.ObjectId, ref: "File" },
  events: [{ type: mongoose.Schema.Types.ObjectId, ref: "SecurityEvent" }],
  eventCount: { type: Number, default: 0 },

  firstEventAt: Date,
  lastEventAt: Date,

  // Phase 8 (SOAR): populated after runSoarEngine() responds to an event correlated into this
  // incident - purely additive, defaults leave every pre-Phase-8 incident unaffected.
  automationStatus: { type: String, enum: ["none", "triggered", "completed", "failed"], default: "none" },
  executedPlaybooks: [
    {
      playbookId: { type: mongoose.Schema.Types.ObjectId, ref: "Playbook" },
      playbookName: String,
      executionId: { type: mongoose.Schema.Types.ObjectId, ref: "AutomationExecution" },
      ranAt: { type: Date, default: Date.now }
    }
  ],
  actionTimeline: [
    {
      type: String,
      success: Boolean,
      detail: String,
      timestamp: { type: Date, default: Date.now }
    }
  ],
  responseDurationMs: { type: Number, default: null }
}, { timestamps: true });

incidentSchema.index({ owner: 1, lastEventAt: -1 });
incidentSchema.index({ owner: 1, status: 1 });

export default mongoose.model("Incident", incidentSchema);
