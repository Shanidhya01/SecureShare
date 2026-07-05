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
  // Phase 9.5: siemType relabeled LOGIN -> LOGIN_SUCCESS to match that phase's spec naming.
  // "LOGIN" is kept in the SecurityEvent.siemType enum below purely so historical documents
  // written before this change remain valid - no code reads/writes "LOGIN" going forward.
  login: { siemType: "LOGIN_SUCCESS", severity: "INFO", category: "AUTH", label: "Login" },
  register: { siemType: "REGISTER", severity: "INFO", category: "AUTH", label: "Account Registered" },
  session_created: { siemType: "SESSION_CREATED", severity: "INFO", category: "SESSION", label: "Session Created" },
  upload: { siemType: "UPLOAD", severity: "INFO", category: "UPLOAD", label: "File Uploaded" },
  download_allowed: { siemType: "DOWNLOAD_ALLOWED", severity: "INFO", category: "DOWNLOAD", label: "Download Allowed" },
  threat_found: { siemType: "THREAT_FOUND", severity: "HIGH", category: "THREAT", label: "Threat Found" },
  signature_verified: { siemType: "SIGNATURE_VERIFIED", severity: "INFO", category: "SIGNATURE", label: "Signature Verified" },
  signature_invalid: { siemType: "SIGNATURE_INVALID", severity: "CRITICAL", category: "SIGNATURE", label: "Signature Invalid" },
  policy_violation: { siemType: "POLICY_VIOLATION", severity: "MEDIUM", category: "ZERO_TRUST", label: "Policy Violation" },

  // --- New types (Phase 7: Threat Intelligence) ---
  ioc_match: { siemType: "IOC_MATCH", severity: "HIGH", category: "THREAT", label: "IOC Match" },
  ioc_lookup: { siemType: "IOC_LOOKUP", severity: "INFO", category: "THREAT", label: "IOC Lookup" },
  threat_intel_match: { siemType: "THREAT_INTEL_MATCH", severity: "CRITICAL", category: "THREAT", label: "Threat Intel Match" },
  mitre_mapping: { siemType: "MITRE_MAPPING", severity: "MEDIUM", category: "THREAT", label: "MITRE Technique Mapped" },
  yara_match: { siemType: "YARA_MATCH", severity: "HIGH", category: "THREAT", label: "YARA Rule Match" },
  provider_error: { siemType: "PROVIDER_ERROR", severity: "LOW", category: "THREAT", label: "Threat Intel Provider Error" },

  // --- New types (Phase 8: SOAR) ---
  playbook_started: { siemType: "PLAYBOOK_STARTED", severity: "INFO", category: "AUTOMATION", label: "Playbook Started" },
  playbook_completed: { siemType: "PLAYBOOK_COMPLETED", severity: "INFO", category: "AUTOMATION", label: "Playbook Completed" },
  playbook_failed: { siemType: "PLAYBOOK_FAILED", severity: "HIGH", category: "AUTOMATION", label: "Playbook Failed" },
  automation_triggered: { siemType: "AUTOMATION_TRIGGERED", severity: "MEDIUM", category: "AUTOMATION", label: "Automation Triggered" },
  automation_skipped: { siemType: "AUTOMATION_SKIPPED", severity: "INFO", category: "AUTOMATION", label: "Automation Skipped" },
  session_revoked_automatically: { siemType: "SESSION_REVOKED_AUTOMATICALLY", severity: "MEDIUM", category: "AUTOMATION", label: "Session Revoked Automatically" },
  file_quarantined_automatically: { siemType: "FILE_QUARANTINED_AUTOMATICALLY", severity: "HIGH", category: "AUTOMATION", label: "File Quarantined Automatically" },
  user_notified: { siemType: "USER_NOTIFIED", severity: "INFO", category: "AUTOMATION", label: "User Notified" },

  // --- New types (Phase 9: IAM / MFA) ---
  login_failed: { siemType: "LOGIN_FAILED", severity: "MEDIUM", category: "IAM", label: "Login Failed" },
  mfa_success: { siemType: "MFA_SUCCESS", severity: "INFO", category: "IAM", label: "MFA Success" },
  mfa_failed: { siemType: "MFA_FAILED", severity: "MEDIUM", category: "IAM", label: "MFA Failed" },
  passkey_login: { siemType: "PASSKEY_LOGIN", severity: "INFO", category: "IAM", label: "Passkey Login" },
  device_trusted: { siemType: "DEVICE_TRUSTED", severity: "LOW", category: "IAM", label: "Device Trusted" },
  policy_block: { siemType: "POLICY_BLOCK", severity: "HIGH", category: "IAM", label: "Policy Block" },
  step_up_auth: { siemType: "STEP_UP_AUTH", severity: "MEDIUM", category: "IAM", label: "Step-Up Authentication" },

  // --- New types (Phase 9.5: Adaptive Authentication) ---
  impossible_travel: { siemType: "IMPOSSIBLE_TRAVEL", severity: "CRITICAL", category: "IAM", label: "Impossible Travel" },

  // --- New types (Phase 10: Compliance & Governance) ---
  compliance_scan: { siemType: "COMPLIANCE_SCAN", severity: "INFO", category: "COMPLIANCE", label: "Compliance Scan Run" },
  control_passed: { siemType: "CONTROL_PASSED", severity: "INFO", category: "COMPLIANCE", label: "Compliance Control Passed" },
  control_failed: { siemType: "CONTROL_FAILED", severity: "HIGH", category: "COMPLIANCE", label: "Compliance Control Failed" },
  policy_updated: { siemType: "POLICY_UPDATED", severity: "LOW", category: "COMPLIANCE", label: "Compliance Policy Updated" },
  compliance_policy_violation: { siemType: "POLICY_VIOLATION", severity: "MEDIUM", category: "COMPLIANCE", label: "Compliance Policy Violation" },
  report_generated: { siemType: "REPORT_GENERATED", severity: "INFO", category: "COMPLIANCE", label: "Compliance Report Generated" },
  evidence_collected: { siemType: "EVIDENCE_COLLECTED", severity: "INFO", category: "COMPLIANCE", label: "Compliance Evidence Collected" },
  // Phase 10 continuation: overall-run-level pass/fail verdicts (distinct from the per-control
  // control_passed/control_failed above) and a framework-level configuration-change event.
  compliance_failed: { siemType: "COMPLIANCE_FAILED", severity: "HIGH", category: "COMPLIANCE", label: "Compliance Run Failed" },
  compliance_passed: { siemType: "COMPLIANCE_PASSED", severity: "INFO", category: "COMPLIANCE", label: "Compliance Run Passed" },
  framework_updated: { siemType: "FRAMEWORK_UPDATED", severity: "LOW", category: "COMPLIANCE", label: "Compliance Framework Updated" },

  // --- New types (Phase 11: CSPM / Attack Surface Management) ---
  asset_discovered: { siemType: "ASSET_DISCOVERED", severity: "INFO", category: "CLOUD", label: "Cloud Asset Discovered" },
  asset_updated: { siemType: "ASSET_UPDATED", severity: "INFO", category: "CLOUD", label: "Cloud Asset Updated" },
  configuration_scan: { siemType: "CONFIGURATION_SCAN", severity: "INFO", category: "CLOUD", label: "Configuration Scan Run" },
  configuration_failure: { siemType: "CONFIGURATION_FAILURE", severity: "HIGH", category: "CLOUD", label: "Configuration Finding" },
  public_exposure: { siemType: "PUBLIC_EXPOSURE", severity: "HIGH", category: "CLOUD", label: "Public Exposure Detected" },
  weak_tls: { siemType: "WEAK_TLS", severity: "MEDIUM", category: "CLOUD", label: "Weak TLS Configuration" },
  certificate_expiring: { siemType: "CERTIFICATE_EXPIRING", severity: "MEDIUM", category: "CLOUD", label: "Certificate Expiring Soon" },
  certificate_expired: { siemType: "CERTIFICATE_EXPIRED", severity: "CRITICAL", category: "CLOUD", label: "Certificate Expired" },
  missing_security_headers: { siemType: "MISSING_SECURITY_HEADERS", severity: "MEDIUM", category: "CLOUD", label: "Missing Security Headers" },
  cloud_risk_updated: { siemType: "CLOUD_RISK_UPDATED", severity: "INFO", category: "CLOUD", label: "Cloud Risk Score Updated" },
  security_score_updated: { siemType: "SECURITY_SCORE_UPDATED", severity: "INFO", category: "CLOUD", label: "Overall Security Score Updated" },
  cloud_ioc_match: { siemType: "CLOUD_IOC_MATCH", severity: "CRITICAL", category: "CLOUD", label: "Cloud Asset IOC Match" },

  // --- New types (Phase 12: DevSecOps / Software Supply Chain Security) ---
  dependency_vulnerability: { siemType: "DEPENDENCY_VULNERABILITY", severity: "HIGH", category: "DEVSECOPS", label: "Dependency Vulnerability Found" },
  secret_found: { siemType: "SECRET_FOUND", severity: "CRITICAL", category: "DEVSECOPS", label: "Secret Found in Source" },
  sbom_generated: { siemType: "SBOM_GENERATED", severity: "INFO", category: "DEVSECOPS", label: "SBOM Generated" },
  sast_finding: { siemType: "SAST_FINDING", severity: "HIGH", category: "DEVSECOPS", label: "SAST Finding" },
  container_vulnerability: { siemType: "CONTAINER_VULNERABILITY", severity: "HIGH", category: "DEVSECOPS", label: "Container Vulnerability Found" },
  pipeline_failed: { siemType: "PIPELINE_FAILED", severity: "MEDIUM", category: "DEVSECOPS", label: "Pipeline Failed" },
  pipeline_blocked: { siemType: "PIPELINE_BLOCKED", severity: "HIGH", category: "DEVSECOPS", label: "Pipeline Blocked" },
  high_risk_repository: { siemType: "HIGH_RISK_REPOSITORY", severity: "HIGH", category: "DEVSECOPS", label: "High Risk Repository" },
  iac_misconfiguration: { siemType: "IAC_MISCONFIGURATION", severity: "MEDIUM", category: "DEVSECOPS", label: "IaC Misconfiguration" },
  devsecops_scan: { siemType: "DEVSECOPS_SCAN", severity: "INFO", category: "DEVSECOPS", label: "DevSecOps Scan Run" },
  devsecops_risk_updated: { siemType: "DEVSECOPS_RISK_UPDATED", severity: "INFO", category: "DEVSECOPS", label: "DevSecOps Risk Score Updated" },

  // --- New types (Phase 13: Production Hardening & Cloud Platform Operations) ---
  // Category "PLATFORM" is deliberately distinct from "AUTOMATION" - services/soar/soarEngine.js
  // ignores AUTOMATION-category events to prevent automation-triggering-automation loops, but
  // platform ops events SHOULD be able to trigger SOAR playbooks (notify admin, collect
  // diagnostics, etc), so they must not share that category. All of these describe managed cloud
  // dependencies (MongoDB Atlas, Redis Cloud, Cloudinary, ClamAV-on-Render) reachability, not local
  // host resources - this deployment has no VM to monitor CPU/disk/memory on.
  platform_health_changed: { siemType: "PLATFORM_HEALTH_CHANGED", severity: "MEDIUM", category: "PLATFORM", label: "Platform Health Changed" },
  mongodb_offline: { siemType: "MONGODB_OFFLINE", severity: "CRITICAL", category: "PLATFORM", label: "MongoDB Atlas Offline" },
  redis_offline: { siemType: "REDIS_OFFLINE", severity: "MEDIUM", category: "PLATFORM", label: "Redis Cloud Offline" },
  clamav_offline: { siemType: "CLAMAV_OFFLINE", severity: "MEDIUM", category: "PLATFORM", label: "ClamAV Offline" },
  cloudinary_failure: { siemType: "CLOUDINARY_FAILURE", severity: "HIGH", category: "PLATFORM", label: "Cloudinary Failure" },
  queue_failure: { siemType: "QUEUE_FAILURE", severity: "HIGH", category: "PLATFORM", label: "Queue Failure" },
  high_api_latency: { siemType: "HIGH_API_LATENCY", severity: "MEDIUM", category: "PLATFORM", label: "High API Latency" },
  background_job_failed: { siemType: "BACKGROUND_JOB_FAILED", severity: "MEDIUM", category: "PLATFORM", label: "Background Job Failed" },
  backup_completed: { siemType: "BACKUP_COMPLETED", severity: "INFO", category: "PLATFORM", label: "Backup Completed" },
  backup_failed: { siemType: "BACKUP_FAILED", severity: "HIGH", category: "PLATFORM", label: "Backup Failed" },
  platform_report_generated: { siemType: "PLATFORM_REPORT_GENERATED", severity: "INFO", category: "PLATFORM", label: "Platform Report Generated" }
};

export const SEVERITY_LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
export const CATEGORIES = [
  "AUTH", "ENCRYPTION", "SIGNATURE", "ZERO_TRUST", "THREAT", "DLP", "UPLOAD", "DOWNLOAD", "DEVICE", "SESSION", "AUTOMATION", "IAM", "COMPLIANCE", "CLOUD", "DEVSECOPS", "PLATFORM"
];

export function resolveEventMeta(type) {
  return TYPE_META[type] || { siemType: undefined, severity: "INFO", category: undefined, label: type };
}
