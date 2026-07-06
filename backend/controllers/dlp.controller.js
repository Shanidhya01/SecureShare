import DLPScan from "../models/DLPScan.js";
import { logSecurityEvent } from "../services/siem/siemLogger.js";
import { runDLPScan } from "../services/dlp/dlpEngine.js";
import { DETECTORS } from "../services/dlp/detectors/index.js";
import { SEVERITY_ACTION, DETECTOR_ACTION_OVERRIDES } from "../services/dlp/dlpPolicyConfig.js";

/**
 * SCAN (Phase 5) - like Phase 4's threat scan, this is one of the few deliberate moments the
 * server sees plaintext file bytes, scoped to this single request only (never written to disk
 * or logged). The browser POSTs the raw file here after the malware scan and before any
 * client-side encryption; the buffer is inspected in memory for embedded secrets/PII and the
 * result persisted as a DLPScan doc (masked previews + metadata only, never raw matches).
 */
export const scanFile = async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const MAX_SCAN_SIZE = 100 * 1024 * 1024; // matches the frontend's upload size limit
    if (req.file.buffer.length > MAX_SCAN_SIZE) {
      return res.status(400).json({ error: "File too large to scan" });
    }

    const result = runDLPScan(req.file.buffer, {
      originalFilename: req.file.originalname,
      claimedMimeType: req.file.mimetype
    });

    const scan = await DLPScan.create({
      owner: req.user.id,
      ...result
    });

    // Part 8 (SIEM Integration): richer event metadata - pattern, confidence, reason, context,
    // decision, file name, uploader, timestamp - sourced straight from the Part 6 risk report so
    // the SIEM/SOAR pipeline sees the same confidence reasoning a human reviewer would.
    const siemMetadata = {
      matchedPatterns: scan.matchedPatterns,
      severity: scan.severity,
      fileName: scan.originalFilename,
      uploader: req.user.id,
      timestamp: scan.createdAt,
      riskReport: (scan.riskReport || []).map((r) => ({
        pattern: r.pattern,
        confidence: r.confidence,
        reasons: r.reasons,
        context: r.context,
        decision: r.decision
      }))
    };

    if (scan.decision === "block") {
      logSecurityEvent({
        owner: req.user.id,
        type: "dlp_blocked",
        message: `Upload blocked: sensitive data detected (${scan.matchedPatterns.join(", ") || scan.severity + " risk"})`,
        filename: scan.originalFilename,
        ip: req.headers["x-client-ip"] || req.ip,
        metadata: siemMetadata
      }).catch((e) => console.error("Failed to record security event:", e));
    } else if (scan.findings.length > 0) {
      logSecurityEvent({
        owner: req.user.id,
        type: scan.decision === "warn" ? "dlp_warning" : "dlp_sensitive_data_detected",
        message: `Sensitive data detected in "${scan.originalFilename}": ${scan.matchedPatterns.join(", ")}`,
        filename: scan.originalFilename,
        ip: req.headers["x-client-ip"] || req.ip,
        metadata: siemMetadata
      }).catch((e) => console.error("Failed to record security event:", e));
    }

    // Only the verdict/metadata (with masked samples) is ever returned - never raw file content.
    res.json({
      dlpScanId: scan._id,
      scanStatus: scan.scanStatus,
      supported: scan.supported,
      skipReason: scan.skipReason || null,
      truncated: scan.truncated,
      severity: scan.severity,
      decision: scan.decision,
      findings: scan.findings,
      matchedPatterns: scan.matchedPatterns,
      riskReport: scan.riskReport || []
    });
  } catch (err) {
    console.error("DLP scan error:", err);
    res.status(500).json({ error: err?.message || "DLP scan failed" });
  }
};

/* ACKNOWLEDGE - owner explicitly confirms a "require_approval" finding so the upload can proceed.
   Does not re-scan or change the recorded decision/findings; it's an audited override, the same
   spirit as Phase 4's quarantine release. */
export const acknowledgeScan = async (req, res) => {
  const scan = await DLPScan.findOne({ _id: req.params.id, owner: req.user.id });
  if (!scan) return res.sendStatus(404);

  if (scan.consumedByUpload) {
    return res.status(400).json({ error: "This scan result has already been used for another upload" });
  }
  if (scan.decision === "block") {
    return res.status(400).json({ error: "This finding cannot be overridden - upload is blocked" });
  }

  scan.acknowledged = true;
  scan.acknowledgedAt = new Date();
  await scan.save();

  res.json({ message: "Acknowledged", dlpScanId: scan._id });
};

/* SCAN HISTORY - the requesting user's own DLP scans, newest first. */
export const getMyScans = async (req, res) => {
  const scans = await DLPScan.find({ owner: req.user.id }).sort({ createdAt: -1 }).limit(100);
  res.json(scans);
};

/* DLP STATS - summary counts for the DLP Center dashboard: scan volume, policy violations,
   blocked uploads, and the most frequently detected secret/PII types. */
export const getDLPStats = async (req, res) => {
  const scans = await DLPScan.find({ owner: req.user.id }).select("decision severity matchedPatterns findings");

  const stats = {
    totalScans: scans.length,
    bySeverity: { None: 0, Low: 0, Medium: 0, High: 0, Critical: 0 },
    byDecision: { allow: 0, warn: 0, require_approval: 0, block: 0 },
    policyViolations: 0, // any scan whose decision was not a plain "allow"
    blockedUploads: 0,
    topDetectedTypes: []
  };

  const typeCounts = {};
  for (const scan of scans) {
    if (stats.bySeverity[scan.severity] !== undefined) stats.bySeverity[scan.severity]++;
    if (stats.byDecision[scan.decision] !== undefined) stats.byDecision[scan.decision]++;
    if (scan.decision !== "allow") stats.policyViolations++;
    if (scan.decision === "block") stats.blockedUploads++;

    for (const finding of scan.findings || []) {
      typeCounts[finding.detectorId] = (typeCounts[finding.detectorId] || 0) + finding.count;
    }
  }

  const labelById = Object.fromEntries(DETECTORS.map((d) => [d.id, d.label]));
  stats.topDetectedTypes = Object.entries(typeCounts)
    .map(([detectorId, count]) => ({ detectorId, label: labelById[detectorId] || detectorId, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  res.json(stats);
};

/* POLICY - read-only view of the currently configured DLP policy (services/dlp/dlpPolicyConfig.js).
   Tuned in code, not via this API - mirrors how Phase 4's RISK_CONFIG is exposed/edited. */
export const getDLPPolicy = async (req, res) => {
  res.json({
    severityAction: SEVERITY_ACTION,
    detectorOverrides: DETECTOR_ACTION_OVERRIDES,
    detectors: DETECTORS.map((d) => ({ id: d.id, label: d.label, category: d.category, severity: d.severity }))
  });
};

/* BLOCKED UPLOADS - files whose DLP scan resulted in a hard block (kept for symmetry with Phase
   4's quarantined-files view, even though a blocked upload never actually creates a File doc -
   this surfaces the DLPScan records themselves). */
export const getBlockedScans = async (req, res) => {
  const scans = await DLPScan.find({ owner: req.user.id, decision: "block" }).sort({ createdAt: -1 }).limit(100);
  res.json(scans);
};
