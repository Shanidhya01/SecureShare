import mongoose from "mongoose";

/**
 * AI Security Assistant: an audit record of every Gemini interaction (threat explanation,
 * incident summary, chat turn). Nothing the assistant generates disappears after the response -
 * this is what backs the "Recent AI Insights" view and lets a user/admin review what the AI said
 * and why. Same indexing convention as SecurityEvent ({owner, createdAt: -1}).
 *
 * `prompt` is stored for audit/debugging (it never contains raw file plaintext - only the
 * metadata context assembled by aiExplanationService.js/etc, same "metadata only" rule
 * SecurityEvent.metadata already follows).
 */
const aiInsightSchema = new mongoose.Schema(
  {
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },

    type: {
      type: String,
      required: true,
      enum: ["threat_explanation", "incident_summary", "chat_response", "risk_explanation"]
    },

    // What the explanation/summary was about, if anything - null for chat turns with no single source.
    sourceType: {
      type: String,
      enum: ["ThreatScan", "DLPScan", "File", "SecurityEvent", null],
      default: null
    },
    sourceId: { type: mongoose.Schema.Types.ObjectId, default: null },

    prompt: String,
    response: mongoose.Schema.Types.Mixed,

    model: String,

    status: { type: String, enum: ["ok", "error", "skipped"], required: true },
    errorMessage: String
  },
  { timestamps: true }
);

aiInsightSchema.index({ owner: 1, createdAt: -1 });

export default mongoose.model("AIInsight", aiInsightSchema);
