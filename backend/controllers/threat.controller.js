import ThreatScan from "../models/ThreatScan.js";
import File from "../models/File.js";
import SecurityEvent from "../models/SecurityEvent.js";
import { runThreatScan } from "../services/threatScanService.js";

/**
 * SCAN (Phase 4) - the one deliberate moment the server sees plaintext file bytes, and only for
 * the duration of this request. The browser POSTs the raw, unencrypted file here BEFORE doing
 * any client-side encryption; the buffer is scanned in memory (magic bytes, hashes, ClamAV,
 * VirusTotal) and never written to disk or logged. The result is persisted as a ThreatScan doc
 * (metadata + hashes + verdict only - never the file content itself) and its id is returned so
 * the client can reference it when it later uploads the actual encrypted file.
 */
export const scanFile = async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const MAX_SCAN_SIZE = 100 * 1024 * 1024; // matches the frontend's upload size limit
    if (req.file.buffer.length > MAX_SCAN_SIZE) {
      return res.status(400).json({ error: "File too large to scan" });
    }

    const result = await runThreatScan(req.file.buffer, {
      originalFilename: req.file.originalname,
      claimedMimeType: req.file.mimetype
    });

    const scan = await ThreatScan.create({
      owner: req.user.id,
      ...result
    });

    if (scan.quarantined) {
      SecurityEvent.create({
        owner: req.user.id,
        type: "file_quarantined",
        message: `Upload blocked: ${scan.riskLevel} risk (${scan.clamav.threatNames.concat(scan.virusTotal.threatNames).join(", ") || scan.riskLevel + " risk signals"})`,
        filename: scan.originalFilename,
        ip: req.headers["x-client-ip"] || req.ip
      }).catch((e) => console.error("Failed to record security event:", e));
    }

    // Only the verdict/metadata is ever returned - never file content, never raw magic bytes
    // beyond the short display sample already capped in the schema.
    res.json({
      scanId: scan._id,
      scanStatus: scan.scanStatus,
      riskLevel: scan.riskLevel,
      quarantined: scan.quarantined,
      mimeMismatch: scan.mimeMismatch,
      claimedMimeType: scan.claimedMimeType,
      detectedMimeType: scan.detectedMimeType,
      dangerousExtension: scan.dangerousExtension,
      dangerousDetectedType: scan.dangerousDetectedType,
      hasMacros: scan.hasMacros,
      isEncryptedArchive: scan.isEncryptedArchive,
      hashes: scan.hashes,
      clamav: scan.clamav,
      virusTotal: scan.virusTotal
    });
  } catch (err) {
    console.error("Threat scan error:", err);
    res.status(500).json({ error: err?.message || "Scan failed" });
  }
};

/* SCAN HISTORY - the requesting user's own scans, newest first. */
export const getMyScans = async (req, res) => {
  const scans = await ThreatScan.find({ owner: req.user.id }).sort({ createdAt: -1 }).limit(100);
  res.json(scans);
};

/* QUARANTINED FILES - files owned by the user that were blocked from download due to risk. */
export const getQuarantinedFiles = async (req, res) => {
  const files = await File.find({ owner: req.user.id, quarantined: true })
    .sort({ createdAt: -1 })
    .populate("scanId");
  res.json(files);
};

/* THREAT STATS - summary counts for the Threat Center dashboard. */
export const getThreatStats = async (req, res) => {
  const [scans, quarantinedCount] = await Promise.all([
    ThreatScan.find({ owner: req.user.id }).select("riskLevel clamav.status virusTotal.status quarantined"),
    File.countDocuments({ owner: req.user.id, quarantined: true })
  ]);

  const stats = {
    totalScans: scans.length,
    quarantinedFiles: quarantinedCount,
    byRiskLevel: { Low: 0, Medium: 0, High: 0, Critical: 0 },
    malwareDetections: 0,
    clamavUnavailableCount: 0
  };

  for (const scan of scans) {
    if (stats.byRiskLevel[scan.riskLevel] !== undefined) stats.byRiskLevel[scan.riskLevel]++;
    if (scan.clamav?.status === "infected" || scan.virusTotal?.status === "malicious") stats.malwareDetections++;
    if (scan.clamav?.status === "unavailable") stats.clamavUnavailableCount++;
  }

  res.json(stats);
};

/* RELEASE FROM QUARANTINE - owner override, e.g. after confirming a false positive. Does not
   re-scan; simply restores download access. Logged as a security event for auditability. */
export const releaseFromQuarantine = async (req, res) => {
  const file = await File.findOne({ _id: req.params.id, owner: req.user.id });
  if (!file) return res.sendStatus(404);

  file.quarantined = false;
  await file.save();

  SecurityEvent.create({
    owner: req.user.id,
    type: "file_quarantined",
    message: `Quarantine manually released for "${file.filename}"`,
    file: file._id,
    filename: file.filename
  }).catch((e) => console.error("Failed to record security event:", e));

  res.json({ message: "Released from quarantine" });
};
