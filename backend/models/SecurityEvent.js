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
    enum: [
      "new_device", "device_removed", "session_revoked", "download_denied", "file_quarantined",
      // Phase 5: DLP scan outcomes worth surfacing in the security activity feed.
      "dlp_blocked", "dlp_warning", "dlp_sensitive_data_detected",
      // Phase 6 (SIEM): previously-unlogged events, added to the activity feed. Additive only -
      // none of the values above changed meaning or were removed.
      "login", "register", "session_created", "upload", "download_allowed",
      "threat_found", "signature_verified", "signature_invalid", "policy_violation"
    ]
  },
  message: String,

  file: { type: mongoose.Schema.Types.ObjectId, ref: "File" },
  filename: String,

  deviceId: String,
  ip: String,
  country: String,

  // Phase 6 (SIEM): additive, optional fields layered on top of the original schema above so
  // existing consumers (Audit Logs page, /api/security/events, historical docs) are unaffected.
  // `type` remains the source of truth for legacy readers; `siemType` is the canonical taxonomy
  // used by the SIEM/SOC views. See services/siem/eventCatalog.js for the type -> meta mapping.
  siemType: {
    type: String,
    enum: [
      "LOGIN", "REGISTER", "UPLOAD", "DOWNLOAD_ALLOWED", "DOWNLOAD_DENIED",
      "THREAT_FOUND", "FILE_QUARANTINED",
      "DLP_BLOCK", "DLP_WARNING", "DLP_SENSITIVE_DATA",
      "SIGNATURE_VERIFIED", "SIGNATURE_INVALID",
      "DEVICE_NEW", "DEVICE_REVOKED",
      "SESSION_CREATED", "SESSION_REVOKED",
      "POLICY_VIOLATION"
    ]
  },
  severity: { type: String, enum: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], default: "INFO" },
  category: {
    type: String,
    enum: ["AUTH", "ENCRYPTION", "SIGNATURE", "ZERO_TRUST", "THREAT", "DLP", "UPLOAD", "DOWNLOAD", "DEVICE", "SESSION"]
  },
  // Set by the correlation engine once this event has been grouped into an Incident.
  correlationId: String,
  // Small structured extras (riskLevel, hash, detectorIds, etc.) - never raw file content.
  metadata: mongoose.Schema.Types.Mixed,

  createdAt: { type: Date, default: Date.now }
});

securityEventSchema.index({ owner: 1, createdAt: -1 });
securityEventSchema.index({ owner: 1, severity: 1, createdAt: -1 });
securityEventSchema.index({ owner: 1, correlationId: 1 });

export default mongoose.model("SecurityEvent", securityEventSchema);
