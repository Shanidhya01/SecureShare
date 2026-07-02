/**
 * Configurable risk classification for uploaded files (Phase 4). Pure function - no DB/network
 * access - so callers (threat.controller.js) gather signals first (magic bytes, ClamAV,
 * VirusTotal) and this module just applies the classification rules.
 *
 * Extend/override RISK_CONFIG (or pass a custom config into classifyRisk) to tune the rule set
 * without touching call sites - e.g. to add extensions, change thresholds, or wire in additional
 * signals from a future scan engine.
 */

export const RISK_CONFIG = {
  dangerousExtensions: [
    ".exe", ".dll", ".bat", ".cmd", ".com", ".scr", ".msi", ".msp",
    ".vbs", ".vbe", ".js", ".jse", ".ws", ".wsf", ".ps1", ".psm1",
    ".jar", ".apk", ".sh", ".app", ".deb", ".rpm", ".reg", ".lnk", ".hta", ".cpl"
  ],
  macroExtensions: [".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".xlam", ".ppam", ".sldm"],
  // MIME types that indicate the file's actual (magic-byte-detected) content is executable,
  // independent of whatever extension/filename it was uploaded under. This is what catches a
  // renamed "invoice.pdf" that's really a Windows PE binary - the classic disguise attack.
  dangerousDetectedMimeTypes: ["application/x-msdownload", "application/x-elf"],
  // VirusTotal: this many or more engines flagging malicious is treated as a confirmed detection;
  // below that (but > 0) is "suspicious" rather than an outright malware verdict.
  virusTotalMaliciousThreshold: 2
};

export function getFileExtension(filename = "") {
  const match = /\.[^./\\]+$/.exec(filename || "");
  return match ? match[0].toLowerCase() : "";
}

/**
 * @param {object} signals
 * @param {boolean} signals.malwareDetected - true if ClamAV or VirusTotal found a confirmed threat
 * @param {boolean} signals.dangerousExtension - claimed filename ends in a dangerous extension
 * @param {boolean} [signals.dangerousDetectedType] - magic-byte-detected content is executable,
 *   regardless of what extension/MIME the upload claimed (catches renamed/disguised binaries)
 * @param {boolean} signals.hasMacros
 * @param {boolean} signals.isEncryptedArchive
 * @param {boolean} signals.mimeMismatch
 * @param {boolean} [signals.virusTotalSuspicious] - VT flagged it but below the malicious threshold
 * @returns {"Low"|"Medium"|"High"|"Critical"}
 */
export function classifyRisk(signals) {
  const {
    malwareDetected,
    dangerousExtension,
    dangerousDetectedType,
    hasMacros,
    isEncryptedArchive,
    mimeMismatch,
    virusTotalSuspicious
  } = signals;

  if (malwareDetected) return "Critical";

  // A disguised executable (real content is a binary, but it's masquerading as something else)
  // is treated as severely as an outright malware hit - the mismatch itself is the attack.
  if (dangerousDetectedType && mimeMismatch) return "Critical";
  if (dangerousExtension && (hasMacros || isEncryptedArchive || mimeMismatch)) return "Critical";

  if (dangerousExtension || dangerousDetectedType) return "High";
  if (hasMacros && mimeMismatch) return "High";
  if (virusTotalSuspicious) return "High";

  if (hasMacros) return "Medium";
  if (isEncryptedArchive) return "Medium";
  if (mimeMismatch) return "Medium";

  return "Low";
}

export function shouldQuarantine(riskLevel) {
  return riskLevel === "Critical" || riskLevel === "High";
}
