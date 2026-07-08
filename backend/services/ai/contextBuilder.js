/**
 * AI Security Assistant: assembles real, scoped data summaries from every existing subsystem for
 * chatService.js (Feature 1 Q&A) to hand to Gemini. Every function here queries the same models
 * (and mirrors the same aggregate shapes) the domain's own dashboard controller already returns
 * to the UI - this file never reimplements a scanner/engine, it only reads already-computed
 * results (File.riskLevel, DLPScan.severity, ComplianceAssessment.score, etc).
 *
 * Every function takes a `scope = { ownerId, isAdmin }` and returns a plain JSON-serializable
 * object - safe to pass straight into promptTemplates.formatContextBlock(). Missing/inapplicable
 * data is represented explicitly (empty arrays, zero counts, or `{ restricted: true }`), never
 * omitted, so the no-hallucination prompt clause has something concrete to point at.
 */
import mongoose from "mongoose";
import ThreatScan from "../../models/ThreatScan.js";
import DLPScan from "../../models/DLPScan.js";
import File from "../../models/File.js";
import SecurityEvent from "../../models/SecurityEvent.js";
import Incident from "../../models/Incident.js";
import AutomationExecution from "../../models/AutomationExecution.js";
import ComplianceAssessment from "../../models/ComplianceAssessment.js";
import ComplianceControl from "../../models/ComplianceControl.js";
import DevSecOpsFinding from "../../models/DevSecOpsFinding.js";
import CloudFinding from "../../models/CloudFinding.js";
import Asset from "../../models/Asset.js";
import PlatformAlert from "../../models/PlatformAlert.js";
import PlatformHealthSnapshot from "../../models/PlatformHealthSnapshot.js";
import User from "../../models/User.js";
import { SEVERITY_LEVELS, CATEGORIES } from "../siem/eventCatalog.js";

const DAY_MS = 24 * 60 * 60 * 1000;
const RISK_RANK = { None: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
const zeroInit = (keys) => Object.fromEntries(keys.map((k) => [k, 0]));

export async function getThreatSummary({ ownerId }) {
  const since = new Date(Date.now() - DAY_MS);
  const scans = await ThreatScan.find({ owner: ownerId }).select("riskLevel quarantined clamav virusTotal createdAt originalFilename");
  const byRiskLevel = zeroInit(["Low", "Medium", "High", "Critical"]);
  let malwareDetections = 0;
  const recentQuarantines = [];
  for (const s of scans) {
    if (byRiskLevel[s.riskLevel] !== undefined) byRiskLevel[s.riskLevel]++;
    if (s.clamav?.status === "infected" || s.virusTotal?.status === "malicious") malwareDetections++;
    if (s.quarantined) recentQuarantines.push({ filename: s.originalFilename, riskLevel: s.riskLevel, at: s.createdAt });
  }
  return {
    totalScans: scans.length,
    scansToday: scans.filter((s) => s.createdAt >= since).length,
    byRiskLevel,
    malwareDetections,
    recentQuarantines: recentQuarantines.sort((a, b) => new Date(b.at) - new Date(a.at)).slice(0, 10)
  };
}

export async function getDLPSummary({ ownerId }) {
  const scans = await DLPScan.find({ owner: ownerId }).select("decision severity matchedPatterns findings createdAt originalFilename");
  const bySeverity = zeroInit(["None", "Low", "Medium", "High", "Critical"]);
  const byDecision = zeroInit(["allow", "warn", "require_approval", "block"]);
  let policyViolations = 0;
  let blockedUploads = 0;
  const typeCounts = {};
  for (const s of scans) {
    if (bySeverity[s.severity] !== undefined) bySeverity[s.severity]++;
    if (byDecision[s.decision] !== undefined) byDecision[s.decision]++;
    if (s.decision !== "allow") policyViolations++;
    if (s.decision === "block") blockedUploads++;
    for (const f of s.findings || []) typeCounts[f.detectorId] = (typeCounts[f.detectorId] || 0) + f.count;
  }
  const topDetectedTypes = Object.entries(typeCounts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([detectorId, count]) => ({ detectorId, count }));
  return { totalScans: scans.length, bySeverity, byDecision, policyViolations, blockedUploads, topDetectedTypes };
}

export async function getSIEMSummary({ ownerId }) {
  const since = new Date(Date.now() - DAY_MS);
  const events = await SecurityEvent.find({ owner: ownerId, createdAt: { $gte: since } }).select("severity category createdAt");
  const bySeverity = zeroInit(SEVERITY_LEVELS);
  const byCategory = zeroInit(CATEGORIES);
  for (const e of events) {
    if (bySeverity[e.severity] !== undefined) bySeverity[e.severity]++;
    if (e.category && byCategory[e.category] !== undefined) byCategory[e.category]++;
  }
  const incidentsByStatus = await Incident.aggregate([
    { $match: { owner: new mongoose.Types.ObjectId(ownerId) } },
    { $group: { _id: "$status", count: { $sum: 1 } } }
  ]).catch(() => []);
  const openIncidents = await Incident.countDocuments({ owner: ownerId, status: { $ne: "resolved" } });
  const criticalEvents = await SecurityEvent.find({ owner: ownerId, severity: { $in: ["HIGH", "CRITICAL"] } })
    .sort({ createdAt: -1 })
    .limit(10)
    .select("type siemType severity message createdAt");
  return {
    eventsToday: events.length,
    bySeverity,
    byCategory,
    incidentsByStatus: Object.fromEntries(incidentsByStatus.map((i) => [i._id, i.count])),
    openIncidents,
    criticalEvents: criticalEvents.map((e) => ({ type: e.siemType || e.type, severity: e.severity, message: e.message, at: e.createdAt }))
  };
}

export async function getSOARSummary({ ownerId }) {
  const executions = await AutomationExecution.find({ owner: ownerId })
    .sort({ createdAt: -1 })
    .limit(50)
    .select("ruleName playbookName status durationMs actionsExecuted createdAt");
  const byStatus = zeroInit(["completed", "partial", "failed"]);
  const ruleCounts = {};
  for (const e of executions) {
    if (byStatus[e.status] !== undefined) byStatus[e.status]++;
    if (e.ruleName) ruleCounts[e.ruleName] = (ruleCounts[e.ruleName] || 0) + 1;
  }
  const topRules = Object.entries(ruleCounts).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, count]) => ({ name, count }));
  const successRate = executions.length ? Math.round((byStatus.completed / executions.length) * 100) : 100;
  return {
    recentExecutions: executions.slice(0, 10).map((e) => ({ rule: e.ruleName, playbook: e.playbookName, status: e.status, at: e.createdAt })),
    byStatus,
    topRules,
    successRate
  };
}

export async function getComplianceSummary() {
  const latest = await ComplianceAssessment.find().sort({ evaluatedAt: -1 }).limit(500).select("control status score recommendations evaluatedAt");
  const seen = new Set();
  const current = [];
  for (const a of latest) {
    const key = String(a.control);
    if (seen.has(key)) continue;
    seen.add(key);
    current.push(a);
  }
  const overallScore = current.length ? Math.round(current.reduce((sum, a) => sum + a.score, 0) / current.length) : 100;
  const controlCoverage = zeroInit(["PASS", "FAIL", "PARTIAL", "NOT_APPLICABLE"]);
  for (const a of current) if (controlCoverage[a.status] !== undefined) controlCoverage[a.status]++;
  const failingControlIds = current.filter((a) => a.status === "FAIL").map((a) => a.control);
  const failingControls = await ComplianceControl.find({ _id: { $in: failingControlIds } }).select("title severity category").limit(10);
  return {
    overallScore,
    controlCoverage,
    topFailingControls: failingControls.map((c) => ({ title: c.title, severity: c.severity, category: c.category }))
  };
}

export async function getDevSecOpsSummary() {
  const findings = await DevSecOpsFinding.find({ status: "open" }).select("category severity title recommendation");
  const findingsBySeverity = zeroInit(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
  const findingsByCategory = zeroInit(["DEPENDENCY", "SECRET", "SAST", "CONTAINER", "IAC", "PIPELINE"]);
  for (const f of findings) {
    if (findingsBySeverity[f.severity] !== undefined) findingsBySeverity[f.severity]++;
    if (findingsByCategory[f.category] !== undefined) findingsByCategory[f.category]++;
  }
  const recommendations = [...new Set(findings.filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH").map((f) => f.recommendation).filter(Boolean))].slice(0, 10);
  return { openFindingCount: findings.length, findingsBySeverity, findingsByCategory, recommendations };
}

export async function getCloudSummary() {
  const findings = await CloudFinding.find({ status: "open" }).select("category severity title");
  const findingsBySeverity = zeroInit(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
  const findingsByCategory = zeroInit(["CONFIGURATION", "EXPOSURE", "CERTIFICATE", "THREAT_INTEL"]);
  for (const f of findings) {
    if (findingsBySeverity[f.severity] !== undefined) findingsBySeverity[f.severity]++;
    if (findingsByCategory[f.category] !== undefined) findingsByCategory[f.category]++;
  }
  const highRiskAssets = await Asset.find({ $or: [{ criticality: { $in: ["critical", "high"] } }, { riskScore: { $gte: 60 } }] })
    .sort({ riskScore: -1 })
    .limit(10)
    .select("name type riskScore criticality");
  return { openFindingCount: findings.length, findingsBySeverity, findingsByCategory, highRiskAssets };
}

export async function getPlatformSummary() {
  const latestHealth = await PlatformHealthSnapshot.findOne().sort({ checkedAt: -1 });
  const activeAlerts = await PlatformAlert.find({ active: true }).sort({ triggeredAt: -1 }).limit(10).select("rule severity message triggeredAt");
  return {
    overallStatus: latestHealth?.overallStatus || "UNKNOWN",
    overallScore: latestHealth?.overallScore ?? null,
    components: (latestHealth?.components || []).map((c) => ({ name: c.name, status: c.status, message: c.message })),
    activeAlerts: activeAlerts.map((a) => ({ rule: a.rule, severity: a.severity, message: a.message, at: a.triggeredAt }))
  };
}

/** New aggregation - no existing endpoint returns this. Mirrors the enum-rank-sort pattern used
 *  elsewhere in the backend (e.g. services/dlp/dlpEngine.js's SEVERITY_RANK) since File.riskLevel/
 *  dlpRisk are ordered enum strings, not numeric scores like Asset.riskScore. */
export async function getHighRiskFiles({ ownerId }) {
  const files = await File.find({
    owner: ownerId,
    $or: [{ riskLevel: { $in: ["High", "Critical"] } }, { dlpRisk: { $in: ["High", "Critical"] } }, { threatScore: { $gte: 60 } }]
  })
    .select("originalFilename filename riskLevel dlpRisk threatScore quarantined createdAt")
    .limit(50);

  const ranked = files
    .map((f) => ({
      filename: f.originalFilename || f.filename,
      riskLevel: f.riskLevel,
      dlpRisk: f.dlpRisk,
      threatScore: f.threatScore,
      quarantined: f.quarantined,
      createdAt: f.createdAt,
      _rank: Math.max(RISK_RANK[f.riskLevel] || 0, RISK_RANK[f.dlpRisk] || 0)
    }))
    .sort((a, b) => b._rank - a._rank)
    .slice(0, 10)
    .map(({ _rank, ...rest }) => rest);

  return { highRiskFileCount: files.length, topFiles: ranked };
}

/** New aggregation, admin-only - grouping events across users is inherently a cross-account view,
 *  so a non-admin scope returns an explicit restricted marker rather than silently narrowing to
 *  themselves (which would look like "there are no other active users" - a hallucination risk in
 *  disguise). The prompt's NO_HALLUCINATION_CLAUSE tells Gemini how to represent this. */
export async function getMostActiveUsers({ isAdmin }) {
  if (!isAdmin) return { restricted: true, reason: "Cross-user activity data is only available to administrators." };

  const since = new Date(Date.now() - DAY_MS);
  const grouped = await SecurityEvent.aggregate([
    { $match: { createdAt: { $gte: since } } },
    {
      $group: {
        _id: "$owner",
        totalEvents: { $sum: 1 },
        criticalEvents: { $sum: { $cond: [{ $in: ["$severity", ["HIGH", "CRITICAL"]] }, 1, 0] } }
      }
    },
    { $sort: { totalEvents: -1 } },
    { $limit: 10 }
  ]).catch(() => []);

  const users = await User.find({ _id: { $in: grouped.map((g) => g._id) } }).select("email");
  const emailById = new Map(users.map((u) => [String(u._id), u.email]));

  return {
    restricted: false,
    topUsers: grouped.map((g) => ({ email: emailById.get(String(g._id)) || "unknown", totalEvents: g.totalEvents, criticalEvents: g.criticalEvents }))
  };
}

const SECTION_BUILDERS = {
  threat: getThreatSummary,
  dlp: getDLPSummary,
  siem: getSIEMSummary,
  soar: getSOARSummary,
  compliance: getComplianceSummary,
  devsecops: getDevSecOpsSummary,
  cloud: getCloudSummary,
  platform: getPlatformSummary,
  fileRisk: getHighRiskFiles,
  activeUsers: getMostActiveUsers
};

const KEYWORD_ROUTES = [
  { keywords: ["malware", "blocked", "threat", "quarantine", "scan"], sections: ["threat", "fileRisk"] },
  { keywords: ["dlp", "sensitive", "data loss", "leak"], sections: ["dlp"] },
  { keywords: ["siem", "incident", "event"], sections: ["siem"] },
  { keywords: ["soar", "automat", "playbook"], sections: ["soar"] },
  { keywords: ["complian"], sections: ["compliance"] },
  { keywords: ["devsecops", "dependency", "secret", "pipeline", "sbom", "sast"], sections: ["devsecops"] },
  { keywords: ["cloud", "asset", "certificate", "exposure"], sections: ["cloud"] },
  { keywords: ["platform", "health", "uptime", "alert"], sections: ["platform"] },
  { keywords: ["risk", "highest risk", "dangerous file"], sections: ["fileRisk"] },
  { keywords: ["user", "most active", "who "], sections: ["activeUsers"] }
];

/** Plain keyword routing (no second LLM call) so a question only pulls the domain summaries it
 *  actually needs - keeps prompt size/cost down and gives each section an independent unit that
 *  Feature 8's caching can key on individually later. */
export function selectSections(question) {
  const q = question.toLowerCase();
  const matched = new Set();
  for (const route of KEYWORD_ROUTES) {
    if (route.keywords.some((kw) => q.includes(kw))) route.sections.forEach((s) => matched.add(s));
  }
  return matched.size > 0 ? Array.from(matched) : Object.keys(SECTION_BUILDERS);
}

/**
 * @param {string} question
 * @param {{ ownerId: string, isAdmin: boolean }} scope
 * @returns {Promise<{ sectionsIncluded: string[], [section: string]: any }>}
 */
export async function buildSecurityContext(question, scope) {
  const sections = selectSections(question);
  const context = { sectionsIncluded: sections };
  for (const section of sections) {
    try {
      context[section] = await SECTION_BUILDERS[section](scope);
    } catch (err) {
      context[section] = { error: `Failed to load ${section} data: ${err.message}` };
    }
  }
  return context;
}
