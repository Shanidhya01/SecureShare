/**
 * Phase 7 integration point - called (fire-and-forget) from file.controller.js right after a
 * File doc is created and linked to its ThreatScan/DLPScan, exactly like logSecurityEvent's own
 * call sites there. Enrichment runs against the hashes already computed by the malware scan
 * (ThreatScan.hashes) - by upload time the server no longer has plaintext, so this never
 * re-reads file content. Never throws into the caller; any failure is logged and swallowed, same
 * as every other post-upload side effect in this codebase.
 */
import ThreatIntelScan from "../../models/ThreatIntelScan.js";
import File from "../../models/File.js";
import { runThreatIntelScan } from "./threatIntelEngine.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

export async function runThreatIntelScanAsync(scan, dlpScan, file, ownerId) {
  try {
    const result = await runThreatIntelScan({
      hashes: scan?.hashes,
      filename: file.originalFilename || file.filename
    });

    const intelScan = await ThreatIntelScan.create({
      owner: ownerId,
      fileId: file._id,
      threatScanId: scan?._id || null,
      dlpScanId: dlpScan?._id || null,
      originalFilename: file.originalFilename || file.filename,
      ...result
    });

    await File.findByIdAndUpdate(file._id, {
      threatIntelScanId: intelScan._id,
      threatScore: intelScan.threatScore,
      threatConfidence: intelScan.threatConfidence,
      iocMatchCount: intelScan.iocMatches.length
    });

    if (intelScan.iocMatches.length > 0) {
      logSecurityEvent({
        owner: ownerId,
        type: intelScan.severity === "Critical" ? "threat_intel_match" : "ioc_match",
        message: `Threat intelligence match on "${file.filename}": ${intelScan.iocMatches.map((m) => m.value).join(", ")}`,
        file: file._id,
        filename: file.filename,
        metadata: {
          confidence: intelScan.threatConfidence,
          sources: intelScan.threatSources,
          matchCount: intelScan.iocMatches.length
        }
      }).catch((e) => console.error("Failed to record security event:", e));
    }

    if (intelScan.mitreMapping.length > 0) {
      logSecurityEvent({
        owner: ownerId,
        type: "mitre_mapping",
        message: `MITRE ATT&CK techniques mapped for "${file.filename}": ${intelScan.mitreMapping.map((m) => m.techniqueId).join(", ")}`,
        file: file._id,
        filename: file.filename,
        metadata: { techniques: intelScan.mitreMapping }
      }).catch((e) => console.error("Failed to record security event:", e));
    }

    if (intelScan.yaraMatches.length > 0) {
      logSecurityEvent({
        owner: ownerId,
        type: "yara_match",
        message: `YARA rule match on "${file.filename}": ${intelScan.yaraMatches.map((m) => m.ruleName).join(", ")}`,
        file: file._id,
        filename: file.filename,
        metadata: { rules: intelScan.yaraMatches }
      }).catch((e) => console.error("Failed to record security event:", e));
    }

    for (const providerName of intelScan.providerErrors) {
      logSecurityEvent({
        owner: ownerId,
        type: "provider_error",
        message: `Threat intel provider "${providerName}" failed during enrichment of "${file.filename}"`,
        file: file._id,
        filename: file.filename,
        metadata: { provider: providerName }
      }).catch((e) => console.error("Failed to record security event:", e));
    }
  } catch (err) {
    console.error("Threat intelligence enrichment failed:", err);
  }
}
