/**
 * AI Security Assistant - Feature 2 (AI Threat Explanation). Pure-ish orchestrator, same shape
 * as services/dlp/dlpEngine.js's runDLPScan: loads the referenced detection record(s), cross-
 * links every related record already produced elsewhere in the pipeline (File metadata, DLP
 * findings, Threat Intelligence/MITRE mapping, relevant SIEM events), assembles one unified
 * context object, builds the prompt, calls Gemini, and returns a flat result object for the
 * controller to persist/respond with. Never touches req/res directly, never re-derives data
 * another service already computed (ClamAV/VirusTotal verdicts, DLP findings, IOC/MITRE matches
 * all come from their existing ThreatScan/DLPScan/ThreatIntelScan documents, not recomputed here).
 */
import mongoose from "mongoose";
import ThreatScan from "../../models/ThreatScan.js";
import DLPScan from "../../models/DLPScan.js";
import File from "../../models/File.js";
import SecurityEvent from "../../models/SecurityEvent.js";
import ThreatIntelScan from "../../models/ThreatIntelScan.js";
import { generateContent } from "./geminiService.js";
import { buildThreatExplanationPrompt, buildRiskExplanationPrompt } from "./promptTemplates.js";

const SOURCE_LOADERS = {
  ThreatScan: async (id, ownerId) => ThreatScan.findOne({ _id: id, owner: ownerId }),
  DLPScan: async (id, ownerId) => DLPScan.findOne({ _id: id, owner: ownerId }),
  File: async (id, ownerId) => File.findOne({ _id: id, owner: ownerId }),
  SecurityEvent: async (id, ownerId) => SecurityEvent.findOne({ _id: id, owner: ownerId })
};

/** Compact DLP summary reused across every source type's context - never the raw finding
 *  samples (those stay masked/private to the DLP Center), just enough for the AI to reason about
 *  severity/decision. */
function summarizeDlpScan(scan) {
  if (!scan) return null;
  return {
    severity: scan.severity,
    decision: scan.decision,
    matchedPatterns: scan.matchedPatterns || [],
    findingCount: (scan.findings || []).length
  };
}

/** Compact Threat Intelligence + MITRE ATT&CK summary from the existing ThreatIntelScan doc -
 *  never re-queries any provider, just reads what services/threatIntel/threatIntelIntegration.js
 *  already persisted. */
function summarizeThreatIntel(scan) {
  if (!scan) return null;
  return {
    threatScore: scan.threatScore,
    threatConfidence: scan.threatConfidence,
    severity: scan.severity,
    iocMatches: (scan.iocMatches || []).map((m) => ({ type: m.type, severity: m.severity, source: m.source, description: m.description })),
    mitreMapping: (scan.mitreMapping || []).map((m) => ({ techniqueId: m.techniqueId, name: m.name, tactic: m.tactic })),
    yaraMatches: (scan.yaraMatches || []).map((y) => ({ ruleName: y.ruleName, severity: y.severity }))
  };
}

/** Last 5 SecurityEvents tied to this file (by ref, falling back to filename) - gives the model
 *  real recent activity around this detection without dumping the entire event history. */
async function getRelevantSecurityEvents(ownerId, fileId, filename) {
  const match = { owner: ownerId };
  if (fileId) match.file = fileId;
  else if (filename) match.filename = filename;
  else return [];

  const events = await SecurityEvent.find(match).sort({ createdAt: -1 }).limit(5).select("type siemType severity message createdAt");
  return events.map((e) => ({ type: e.siemType || e.type, severity: e.severity, message: e.message, at: e.createdAt }));
}

/** Loads the File document (and, transitively, its linked DLPScan/ThreatIntelScan) for whichever
 *  source type we started from, so every detection type gets the same fuller picture regardless
 *  of which record the user clicked "Explain with AI" on. */
async function loadLinkedRecords(fileId) {
  if (!fileId) return { file: null, dlpScan: null, threatIntel: null };
  const file = await File.findById(fileId);
  if (!file) return { file: null, dlpScan: null, threatIntel: null };
  const [dlpScan, threatIntel] = await Promise.all([
    file.dlpScanId ? DLPScan.findById(file.dlpScanId) : null,
    file.threatIntelScanId ? ThreatIntelScan.findById(file.threatIntelScanId) : null
  ]);
  return { file, dlpScan, threatIntel };
}

function fileMetadataOf(file) {
  if (!file) return null;
  return {
    filename: file.originalFilename || file.filename,
    mimeType: file.mimeType || null,
    encryptionVersion: file.encryptionVersion,
    quarantined: !!file.quarantined,
    downloadCount: file.downloadCount,
    uploadedAt: file.createdAt
  };
}

/** Builds the single unified context object every source type feeds into
 *  promptTemplates.buildThreatExplanationPrompt/buildRiskExplanationPrompt - every field the
 *  user's UI would already show them (plus what's cross-linked from File/DLPScan/ThreatIntelScan),
 *  nothing more, nothing invented. Missing fields are explicit `null`s/empty arrays so the model
 *  can see they're unavailable rather than guessing at them. */
async function buildUnifiedContext(sourceType, record, requestingUser) {
  let fileId = null;
  let filename = null;
  let clamavResult = null;
  let dlpScanDirect = null;
  let threatType = null;
  let severity = null;
  let detectionReason = [];
  let quarantined = false;
  let riskScore = 0;

  if (sourceType === "ThreatScan") {
    fileId = record.fileId;
    filename = record.originalFilename;
    clamavResult = record.clamav || null;
    severity = record.riskLevel;
    quarantined = !!record.quarantined;
    threatType = record.clamav?.threatNames?.length ? record.clamav.threatNames.join(", ") : record.virusTotal?.threatNames?.join(", ") || null;
    detectionReason = [
      record.clamav?.status === "infected" ? "ClamAV signature match" : null,
      record.virusTotal?.status === "malicious" ? "VirusTotal reputation match" : null,
      record.dangerousDetectedType ? "File content is an executable disguised with a different extension" : null,
      record.mimeMismatch ? "Claimed file type did not match actual file content" : null,
      record.hasMacros ? "File contains macros" : null,
      record.isEncryptedArchive ? "File is an encrypted/password-protected archive" : null
    ].filter(Boolean);
  } else if (sourceType === "DLPScan") {
    fileId = record.fileId;
    filename = record.originalFilename;
    dlpScanDirect = record;
    severity = record.severity;
    threatType = "Data Loss Prevention policy violation";
    detectionReason = (record.findings || []).map((f) => `${f.label} (${f.count} match(es), ${f.confidenceLevel || f.severity} confidence)`);
  } else if (sourceType === "File") {
    fileId = record._id;
    filename = record.originalFilename || record.filename;
    severity = record.riskLevel || record.dlpRisk;
    quarantined = !!record.quarantined;
    riskScore = record.threatScore || 0;
    threatType = record.quarantined ? "Quarantined file" : record.signature ? "Signed file" : null;
    detectionReason = [
      record.quarantined ? "File was quarantined by the malware scanner" : null,
      record.dlpDecision && record.dlpDecision !== "allow" ? `DLP decision: ${record.dlpDecision}` : null
    ].filter(Boolean);
  } else if (sourceType === "SecurityEvent") {
    fileId = record.file;
    filename = record.filename;
    severity = record.severity;
    threatType = record.siemType || record.type;
    detectionReason = record.message ? [record.message] : [];
  }

  const { file, dlpScan, threatIntel } = await loadLinkedRecords(fileId);
  const effectiveDlpScan = dlpScanDirect || dlpScan;
  if (!riskScore) riskScore = file?.threatScore || threatIntel?.threatScore || 0;
  if (!filename) filename = fileMetadataOf(file)?.filename || null;

  const relevantSiemEvents = await getRelevantSecurityEvents(requestingUser.id, fileId, filename);

  return {
    sourceType,
    fileName: filename,
    threatType,
    severity: severity || null,
    riskScore,
    detectionReason,
    clamavResult,
    dlpFindings: summarizeDlpScan(effectiveDlpScan),
    threatIntelligence: summarizeThreatIntel(threatIntel),
    mitreMapping: threatIntel ? summarizeThreatIntel(threatIntel).mitreMapping : [],
    fileMetadata: fileMetadataOf(file),
    quarantined,
    userRole: requestingUser?.role || null,
    timestamp: record.createdAt || null,
    relevantSiemEvents
  };
}

/** Best-effort JSON parse of Gemini's response text - the prompt asks for raw JSON, but models
 *  occasionally wrap it in markdown fences anyway, so those are stripped before parsing. Returns
 *  null (never throws) if the text isn't valid JSON, so the controller can fall back cleanly. */
function parseStructuredResponse(text) {
  const cleaned = text.trim().replace(/^```(?:json)?/i, "").replace(/```$/, "").trim();
  try {
    return JSON.parse(cleaned);
  } catch {
    return null;
  }
}

async function runExplanation(sourceType, sourceId, requestingUser, promptBuilder) {
  const loader = SOURCE_LOADERS[sourceType];
  if (!loader || !mongoose.isValidObjectId(sourceId)) {
    return { status: "error", prompt: null, explanation: null, rawText: null, errorMessage: "Invalid sourceType or sourceId" };
  }

  const record = await loader(sourceId, requestingUser.id);
  if (!record) {
    return { status: "error", prompt: null, explanation: null, rawText: null, errorMessage: "Referenced record not found" };
  }

  const context = await buildUnifiedContext(sourceType, record, requestingUser);
  const prompt = promptBuilder(context);

  const result = await generateContent(prompt);

  if (result.status === "skipped") {
    return { status: "skipped", prompt, explanation: null, rawText: null, errorMessage: null };
  }
  if (result.status === "error") {
    return { status: "error", prompt, explanation: null, rawText: null, errorMessage: result.message };
  }

  const explanation = parseStructuredResponse(result.text);
  if (!explanation) {
    return { status: "error", prompt, explanation: null, rawText: result.text, errorMessage: "Gemini response was not valid JSON" };
  }

  return { status: "ok", prompt, explanation, rawText: result.text, errorMessage: null };
}

/**
 * Feature 2 (AI Threat Explanation). Full structured explanation: executive summary, what
 * happened, why it was detected, business/technical impact, risk level, recommended actions,
 * prevention tips.
 * @param {"ThreatScan"|"DLPScan"|"File"|"SecurityEvent"} sourceType
 * @param {string} sourceId
 * @param {{id: string, role?: string}} requestingUser
 */
export async function explainThreat(sourceType, sourceId, requestingUser) {
  return runExplanation(sourceType, sourceId, requestingUser, buildThreatExplanationPrompt);
}

/**
 * Feature 4 (AI Risk Explanation). Same context-gathering pipeline as explainThreat, but asks
 * Gemini to reason specifically about why the risk score/level is what it is, rather than a full
 * incident narrative - reuses everything above rather than duplicating the loader/context/parse
 * logic for a near-identical feature.
 * @param {"ThreatScan"|"DLPScan"|"File"|"SecurityEvent"} sourceType
 * @param {string} sourceId
 * @param {{id: string, role?: string}} requestingUser
 */
export async function explainRisk(sourceType, sourceId, requestingUser) {
  return runExplanation(sourceType, sourceId, requestingUser, buildRiskExplanationPrompt);
}
