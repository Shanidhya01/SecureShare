/**
 * Orchestrates a full Phase 4 threat scan of a plaintext file buffer: magic-byte type detection,
 * MIME-mismatch check, extension-based heuristics, hashing, ClamAV, and VirusTotal - then applies
 * the risk engine. Returns a plain object matching the ThreatScan schema's scan-result fields;
 * callers (threat.controller.js, file.controller.js's legacy v1 upload) are responsible for
 * actually persisting a ThreatScan document with the right owner/fileId.
 *
 * This is the only place in the codebase that touches plaintext file bytes for scanning purposes
 * - the buffer passed in is never written to disk or logged, and goes out of scope (eligible for
 * GC) as soon as the caller's request handler returns.
 */
import { detectFileType, isEncryptedZip } from "../utils/magicBytes.js";
import { computeFileHashes } from "../utils/fileHashes.js";
import { scanBufferWithClamAV } from "./clamavScanner.js";
import { lookupHashOnVirusTotal } from "./virusTotalLookup.js";
import { classifyRisk, shouldQuarantine, getFileExtension, RISK_CONFIG } from "./riskEngine.js";

const GENERIC_CLAIMED_TYPES = new Set(["", "application/octet-stream", "application/x-www-form-urlencoded"]);

/** A mismatch is only flagged when both sides name a specific, differing type - a browser
 *  sending a generic/empty MIME type isn't itself suspicious, so it isn't penalized. */
function isMimeMismatch(claimedMimeType, detectedMimeType) {
  if (!claimedMimeType || GENERIC_CLAIMED_TYPES.has(claimedMimeType.toLowerCase())) return false;
  if (!detectedMimeType || detectedMimeType === "application/octet-stream") return false;
  return claimedMimeType.toLowerCase() !== detectedMimeType.toLowerCase();
}

/**
 * @param {Buffer} buffer - plaintext file content, never persisted
 * @param {{ originalFilename: string, claimedMimeType: string }} meta
 */
export async function runThreatScan(buffer, { originalFilename, claimedMimeType }) {
  const { mime: detectedMimeType, hex: magicBytesHex } = detectFileType(buffer);
  const mimeMismatch = isMimeMismatch(claimedMimeType, detectedMimeType);
  const extension = getFileExtension(originalFilename);
  const dangerousExtension = RISK_CONFIG.dangerousExtensions.includes(extension);
  const dangerousDetectedType = RISK_CONFIG.dangerousDetectedMimeTypes.includes(detectedMimeType);
  const hasMacros = RISK_CONFIG.macroExtensions.includes(extension);
  const isEncryptedArchive = isEncryptedZip(buffer);
  const hashes = computeFileHashes(buffer);

  const [clamav, virusTotal] = await Promise.all([
    scanBufferWithClamAV(buffer),
    lookupHashOnVirusTotal(hashes.sha256)
  ]);

  const malwareDetected = clamav.status === "infected" || virusTotal.status === "malicious";
  const virusTotalSuspicious = virusTotal.status === "suspicious";

  const riskLevel = classifyRisk({
    malwareDetected,
    dangerousExtension,
    dangerousDetectedType,
    hasMacros,
    isEncryptedArchive,
    mimeMismatch,
    virusTotalSuspicious
  });
  const quarantined = shouldQuarantine(riskLevel);

  return {
    originalFilename,
    fileSizeBytes: buffer.length,
    claimedMimeType: claimedMimeType || null,
    detectedMimeType,
    mimeMismatch,
    extension,
    dangerousExtension,
    dangerousDetectedType,
    hasMacros,
    isEncryptedArchive,
    magicBytesHex,
    hashes,
    clamav: {
      status: clamav.status,
      engineVersion: clamav.engineVersion || null,
      scannedAt: new Date(),
      threatNames: clamav.threatNames || []
    },
    virusTotal: {
      status: virusTotal.status,
      maliciousCount: virusTotal.maliciousCount || 0,
      suspiciousCount: virusTotal.suspiciousCount || 0,
      totalEngines: virusTotal.totalEngines || 0,
      threatNames: virusTotal.threatNames || [],
      checkedAt: new Date()
    },
    riskLevel,
    quarantined,
    scanStatus: "completed"
  };
}
