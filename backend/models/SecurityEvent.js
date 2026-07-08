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
      "threat_found", "signature_verified", "signature_invalid", "policy_violation",
      // Phase 7: Threat Intelligence
      "ioc_match", "ioc_lookup", "threat_intel_match", "mitre_mapping", "yara_match", "provider_error",
      // Phase 8: SOAR
      "playbook_started", "playbook_completed", "playbook_failed", "automation_triggered",
      "automation_skipped", "session_revoked_automatically", "file_quarantined_automatically", "user_notified",
      // Phase 9: IAM / MFA
      "login_failed", "mfa_success", "mfa_failed", "passkey_login", "device_trusted", "policy_block", "step_up_auth",
      // Phase 9.5: Adaptive Authentication
      "impossible_travel",
      // Phase 10: Compliance & Governance
      "compliance_scan", "control_passed", "control_failed", "policy_updated",
      "compliance_policy_violation", "report_generated", "evidence_collected",
      // Phase 10 continuation: overall-run pass/fail verdicts + framework config changes
      "compliance_failed", "compliance_passed", "framework_updated",
      // Phase 11: CSPM / Attack Surface Management
      "asset_discovered", "asset_updated", "configuration_scan", "configuration_failure",
      "public_exposure", "weak_tls", "certificate_expiring", "certificate_expired",
      "missing_security_headers", "cloud_risk_updated", "security_score_updated",
      "cloud_ioc_match",
      // Phase 12: DevSecOps / Software Supply Chain Security
      "dependency_vulnerability", "secret_found", "sbom_generated", "sast_finding",
      "container_vulnerability", "pipeline_failed", "pipeline_blocked", "high_risk_repository",
      "iac_misconfiguration", "devsecops_scan", "devsecops_risk_updated",
      // Phase 13: Production Hardening & Cloud Platform Operations
      "platform_health_changed", "mongodb_offline", "redis_offline", "clamav_offline",
      "cloudinary_failure", "queue_failure", "high_api_latency", "background_job_failed",
      "backup_completed", "backup_failed", "platform_report_generated",
      // AI Security Assistant: Gemini-powered explanations/summaries/chat
      "ai_explanation_requested", "ai_incident_summary_generated", "ai_chat_query", "ai_risk_explanation_requested"
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
      "POLICY_VIOLATION",
      // Phase 7: Threat Intelligence
      "IOC_MATCH", "IOC_LOOKUP", "THREAT_INTEL_MATCH", "MITRE_MAPPING", "YARA_MATCH", "PROVIDER_ERROR",
      // Phase 8: SOAR
      "PLAYBOOK_STARTED", "PLAYBOOK_COMPLETED", "PLAYBOOK_FAILED", "AUTOMATION_TRIGGERED",
      "AUTOMATION_SKIPPED", "SESSION_REVOKED_AUTOMATICALLY", "FILE_QUARANTINED_AUTOMATICALLY", "USER_NOTIFIED",
      // Phase 9: IAM / MFA. "LOGIN" is superseded by "LOGIN_SUCCESS" in Phase 9.5 (see
      // eventCatalog.js) but kept here so historical documents remain valid against this enum.
      "LOGIN", "LOGIN_FAILED", "MFA_SUCCESS", "MFA_FAILED", "PASSKEY_LOGIN", "DEVICE_TRUSTED", "POLICY_BLOCK", "STEP_UP_AUTH",
      // Phase 9.5: Adaptive Authentication
      "LOGIN_SUCCESS", "IMPOSSIBLE_TRAVEL",
      // Phase 10: Compliance & Governance ("POLICY_VIOLATION" already exists above, Phase 6)
      "COMPLIANCE_SCAN", "CONTROL_PASSED", "CONTROL_FAILED", "POLICY_UPDATED",
      "REPORT_GENERATED", "EVIDENCE_COLLECTED",
      // Phase 10 continuation
      "COMPLIANCE_FAILED", "COMPLIANCE_PASSED", "FRAMEWORK_UPDATED",
      // Phase 11: CSPM / Attack Surface Management
      "ASSET_DISCOVERED", "ASSET_UPDATED", "CONFIGURATION_SCAN", "CONFIGURATION_FAILURE",
      "PUBLIC_EXPOSURE", "WEAK_TLS", "CERTIFICATE_EXPIRING", "CERTIFICATE_EXPIRED",
      "MISSING_SECURITY_HEADERS", "CLOUD_RISK_UPDATED", "SECURITY_SCORE_UPDATED", "CLOUD_IOC_MATCH",
      // Phase 12: DevSecOps / Software Supply Chain Security
      "DEPENDENCY_VULNERABILITY", "SECRET_FOUND", "SBOM_GENERATED", "SAST_FINDING",
      "CONTAINER_VULNERABILITY", "PIPELINE_FAILED", "PIPELINE_BLOCKED", "HIGH_RISK_REPOSITORY",
      "IAC_MISCONFIGURATION", "DEVSECOPS_SCAN", "DEVSECOPS_RISK_UPDATED",
      // Phase 13: Production Hardening & Cloud Platform Operations
      "PLATFORM_HEALTH_CHANGED", "MONGODB_OFFLINE", "REDIS_OFFLINE", "CLAMAV_OFFLINE",
      "CLOUDINARY_FAILURE", "QUEUE_FAILURE", "HIGH_API_LATENCY", "BACKGROUND_JOB_FAILED",
      "BACKUP_COMPLETED", "BACKUP_FAILED", "PLATFORM_REPORT_GENERATED",
      // AI Security Assistant: Gemini-powered explanations/summaries/chat
      "AI_EXPLANATION_REQUESTED", "AI_INCIDENT_SUMMARY_GENERATED", "AI_CHAT_QUERY", "AI_RISK_EXPLANATION_REQUESTED"
    ]
  },
  severity: { type: String, enum: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], default: "INFO" },
  category: {
    type: String,
    enum: ["AUTH", "ENCRYPTION", "SIGNATURE", "ZERO_TRUST", "THREAT", "DLP", "UPLOAD", "DOWNLOAD", "DEVICE", "SESSION", "AUTOMATION", "IAM", "COMPLIANCE", "CLOUD", "DEVSECOPS", "PLATFORM", "AI"]
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
