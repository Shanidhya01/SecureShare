import mongoose from "mongoose";

/**
 * Phase 8 (SOAR): an in-app notification, created by the notifyUser/notifyAdmin/sendEmail action
 * handlers (backend/services/soar/actions/). No SMTP/email transport exists in this codebase -
 * "sendEmail" is a documented alias for this in-app mechanism, not real email delivery.
 */
const notificationSchema = new mongoose.Schema(
  {
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    title: { type: String, required: true },
    message: String,
    severity: { type: String, enum: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], default: "INFO" },
    source: { type: String, default: "soar" }, // e.g. "soar", "system"
    relatedFile: { type: mongoose.Schema.Types.ObjectId, ref: "File", default: null },
    relatedExecution: { type: mongoose.Schema.Types.ObjectId, ref: "AutomationExecution", default: null },
    read: { type: Boolean, default: false }
  },
  { timestamps: true }
);

notificationSchema.index({ owner: 1, createdAt: -1 });

export default mongoose.model("Notification", notificationSchema);
