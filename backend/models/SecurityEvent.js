import mongoose from "mongoose";

/**
 * A unified security activity feed for the Security Center dashboard: new-device logins,
 * device removals, session revocations, and denied download attempts against the user's own
 * files. `type: "download_denied"` events double as the "blocked access attempts" feed.
 */
const securityEventSchema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  type: {
    type: String,
    required: true,
    enum: ["new_device", "device_removed", "session_revoked", "download_denied", "file_quarantined"]
  },
  message: String,

  file: { type: mongoose.Schema.Types.ObjectId, ref: "File" },
  filename: String,

  deviceId: String,
  ip: String,
  country: String,

  createdAt: { type: Date, default: Date.now }
});

securityEventSchema.index({ owner: 1, createdAt: -1 });

export default mongoose.model("SecurityEvent", securityEventSchema);
