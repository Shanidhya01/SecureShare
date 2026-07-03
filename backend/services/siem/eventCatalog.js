/**
 * Phase 6 (SIEM): single source of truth mapping every SecurityEvent `type` string (both the
 * original 8 legacy values and the new ones added in Phase 6) to its canonical `siemType`,
 * default `severity`, `category`, and a display `label`. services/siem/siemLogger.js consults
 * this so call sites never need to know severity/category themselves - they just pass the same
 * `type` string they always have.
 */
export const TYPE_META = {
  // --- Legacy types (Phases 1-5), unchanged meaning ---
  new_device: { siemType: "DEVICE_NEW", severity: "INFO", category: "DEVICE", label: "New Device" },
  device_removed: { siemType: "DEVICE_REVOKED", severity: "LOW", category: "DEVICE", label: "Device Removed" },
  session_revoked: { siemType: "SESSION_REVOKED", severity: "LOW", category: "SESSION", label: "Session Revoked" },
  download_denied: { siemType: "DOWNLOAD_DENIED", severity: "MEDIUM", category: "ZERO_TRUST", label: "Download Denied" },
  file_quarantined: { siemType: "FILE_QUARANTINED", severity: "CRITICAL", category: "THREAT", label: "File Quarantined" },
  dlp_blocked: { siemType: "DLP_BLOCK", severity: "HIGH", category: "DLP", label: "DLP Blocked" },
  dlp_warning: { siemType: "DLP_WARNING", severity: "MEDIUM", category: "DLP", label: "DLP Warning" },
  dlp_sensitive_data_detected: { siemType: "DLP_SENSITIVE_DATA", severity: "LOW", category: "DLP", label: "Sensitive Data Detected" },

  // --- New types (Phase 6) ---
  login: { siemType: "LOGIN", severity: "INFO", category: "AUTH", label: "Login" },
  register: { siemType: "REGISTER", severity: "INFO", category: "AUTH", label: "Account Registered" },
  session_created: { siemType: "SESSION_CREATED", severity: "INFO", category: "SESSION", label: "Session Created" },
  upload: { siemType: "UPLOAD", severity: "INFO", category: "UPLOAD", label: "File Uploaded" },
  download_allowed: { siemType: "DOWNLOAD_ALLOWED", severity: "INFO", category: "DOWNLOAD", label: "Download Allowed" },
  threat_found: { siemType: "THREAT_FOUND", severity: "HIGH", category: "THREAT", label: "Threat Found" },
  signature_verified: { siemType: "SIGNATURE_VERIFIED", severity: "INFO", category: "SIGNATURE", label: "Signature Verified" },
  signature_invalid: { siemType: "SIGNATURE_INVALID", severity: "CRITICAL", category: "SIGNATURE", label: "Signature Invalid" },
  policy_violation: { siemType: "POLICY_VIOLATION", severity: "MEDIUM", category: "ZERO_TRUST", label: "Policy Violation" }
};

export const SEVERITY_LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
export const CATEGORIES = [
  "AUTH", "ENCRYPTION", "SIGNATURE", "ZERO_TRUST", "THREAT", "DLP", "UPLOAD", "DOWNLOAD", "DEVICE", "SESSION"
];

export function resolveEventMeta(type) {
  return TYPE_META[type] || { siemType: undefined, severity: "INFO", category: undefined, label: type };
}
