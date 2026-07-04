import Asset from "../models/Asset.js";
import CloudFinding from "../models/CloudFinding.js";
import Certificate from "../models/Certificate.js";
import SecurityScoreSnapshot from "../models/SecurityScoreSnapshot.js";
import SecurityEvent from "../models/SecurityEvent.js";
import Incident from "../models/Incident.js";
import { runCloudScan } from "../services/cloud/cloudScanOrchestrator.js";
import { getScoreHistory } from "../services/cloud/scoreEngine.js";
import { buildCsv, buildJson, buildPdf } from "../services/cloud/cloudReportGenerator.js";
import { logSecurityEvent } from "../services/siem/siemLogger.js";

const DAY_MS = 24 * 60 * 60 * 1000;

/* ============================== DASHBOARD ============================== */

export const getDashboard = async (_req, res) => {
  const [assets, findings, certificates, latestScore, history, recentEvents] = await Promise.all([
    Asset.find().sort({ riskScore: -1 }).lean(),
    CloudFinding.find({ status: "open" }).populate("asset", "name type").sort({ severity: 1, detectedAt: -1 }).lean(),
    Certificate.find().sort({ daysRemaining: 1 }).lean(),
    SecurityScoreSnapshot.findOne().sort({ scannedAt: -1 }).lean(),
    getScoreHistory({ days: 90 }),
    SecurityEvent.find({ category: "CLOUD" }).sort({ createdAt: -1 }).limit(20).lean()
  ]);

  const assetsByType = {};
  for (const a of assets) assetsByType[a.type] = (assetsByType[a.type] || 0) + 1;

  const findingsBySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  const findingsByCategory = { CONFIGURATION: 0, EXPOSURE: 0, CERTIFICATE: 0, THREAT_INTEL: 0 };
  for (const f of findings) {
    findingsBySeverity[f.severity] = (findingsBySeverity[f.severity] || 0) + 1;
    findingsByCategory[f.category] = (findingsByCategory[f.category] || 0) + 1;
  }

  const highRiskAssets = assets.filter((a) => a.criticality === "critical" || a.criticality === "high" || a.riskScore >= 60).slice(0, 20);

  const certSummary = {
    valid: certificates.filter((c) => c.status === "valid").length,
    expiring: certificates.filter((c) => c.status === "expiring").length,
    expired: certificates.filter((c) => c.status === "expired").length,
    unreachable: certificates.filter((c) => c.status === "unreachable").length
  };

  const recommendations = findings
    .filter((f) => ["CRITICAL", "HIGH"].includes(f.severity))
    .slice(0, 10)
    .map((f) => f.recommendation)
    .filter(Boolean);

  res.json({
    overallScore: latestScore?.overallScore ?? 100,
    scores: latestScore
      ? {
          assetScore: latestScore.assetScore,
          configScore: latestScore.configScore,
          exposureScore: latestScore.exposureScore,
          certScore: latestScore.certScore,
          identityScore: latestScore.identityScore,
          complianceScore: latestScore.complianceScore
        }
      : null,
    assetCount: assets.length,
    assetsByType,
    highRiskAssets,
    findingCount: findings.length,
    findingsBySeverity,
    findingsByCategory,
    certificates,
    certSummary,
    recentScans: recentEvents,
    trend: history,
    recommendations: [...new Set(recommendations)]
  });
};

/* ============================== ASSETS ============================== */

export const listAssets = async (req, res) => {
  const filter = {};
  if (req.query.type) filter.type = req.query.type;
  if (req.query.criticality) filter.criticality = req.query.criticality;
  if (req.query.status) filter.status = req.query.status;
  const assets = await Asset.find(filter).sort({ riskScore: -1 }).lean();
  res.json(assets);
};

export const getAsset = async (req, res) => {
  const asset = await Asset.findById(req.params.id).lean();
  if (!asset) return res.sendStatus(404);

  const [findings, related30d, incidents] = await Promise.all([
    CloudFinding.find({ asset: asset._id }).sort({ detectedAt: -1 }).lean(),
    SecurityEvent.find({ category: "CLOUD", createdAt: { $gte: new Date(Date.now() - 30 * DAY_MS) } })
      .sort({ createdAt: -1 })
      .limit(50)
      .lean(),
    Incident.find({ category: "CLOUD" }).sort({ lastEventAt: -1 }).limit(20).lean()
  ]);

  res.json({ asset, findings, relatedEvents: related30d, relatedIncidents: incidents });
};

/* ============================== FINDINGS ============================== */

export const getFindings = async (req, res) => {
  const filter = {};
  if (req.query.category) filter.category = req.query.category;
  if (req.query.severity) filter.severity = req.query.severity;
  if (req.query.status) filter.status = req.query.status || "open";
  else filter.status = "open";

  const findings = await CloudFinding.find(filter).populate("asset", "name type").sort({ severity: 1, detectedAt: -1 }).limit(500).lean();
  res.json(findings);
};

export const acknowledgeFinding = async (req, res) => {
  const finding = await CloudFinding.findByIdAndUpdate(req.params.id, { status: "acknowledged" }, { new: true });
  if (!finding) return res.sendStatus(404);
  res.json(finding);
};

export const resolveFinding = async (req, res) => {
  const finding = await CloudFinding.findByIdAndUpdate(req.params.id, { status: "resolved", resolvedAt: new Date() }, { new: true });
  if (!finding) return res.sendStatus(404);
  res.json(finding);
};

/* ============================== CERTIFICATES ============================== */

export const listCertificates = async (_req, res) => {
  const certificates = await Certificate.find().sort({ daysRemaining: 1 }).lean();
  res.json(certificates);
};

/* ============================== SCORE / HISTORY ============================== */

export const getScore = async (_req, res) => {
  const latest = await SecurityScoreSnapshot.findOne().sort({ scannedAt: -1 }).lean();
  res.json(latest || { overallScore: 100 });
};

export const getHistory = async (req, res) => {
  const days = Number(req.query.days) || 90;
  const history = await getScoreHistory({ days });
  res.json(history);
};

/* ============================== SCAN ============================== */

export const runScan = async (req, res) => {
  const result = await runCloudScan({ owner: req.user.id });
  res.json(result);
};

/* ============================== EXPORT ============================== */

export const exportReport = async (req, res) => {
  const format = (req.params.format || req.query.format || "json").toUpperCase();

  const [assets, findings, certificates, latestScore, trend] = await Promise.all([
    Asset.find().sort({ riskScore: -1 }).lean(),
    CloudFinding.find({ status: "open" }).sort({ severity: 1, detectedAt: -1 }).lean(),
    Certificate.find().sort({ daysRemaining: 1 }).lean(),
    SecurityScoreSnapshot.findOne().sort({ scannedAt: -1 }).lean(),
    getScoreHistory({ days: 90 })
  ]);

  const generatedAt = new Date();
  const filename = `cloud-security-report-${Date.now()}.${format.toLowerCase()}`;
  const overallScore = latestScore?.overallScore ?? 100;
  const scores = latestScore
    ? {
        assetScore: latestScore.assetScore,
        configScore: latestScore.configScore,
        exposureScore: latestScore.exposureScore,
        certScore: latestScore.certScore,
        identityScore: latestScore.identityScore,
        complianceScore: latestScore.complianceScore
      }
    : null;

  await logSecurityEvent({
    owner: req.user.id,
    type: "report_generated",
    message: `Cloud security report generated (${format})`,
    metadata: { format, overallScore }
  });

  const payload = { overallScore, scores, assets, findings, certificates, trend, generatedAt };

  if (format === "PDF") {
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    return buildPdf(payload, res);
  }

  if (format === "CSV") {
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    return res.send(buildCsv(payload));
  }

  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  return res.json(buildJson(payload));
};
