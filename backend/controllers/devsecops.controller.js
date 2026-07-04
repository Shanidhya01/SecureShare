import Repository from "../models/Repository.js";
import DevSecOpsFinding from "../models/DevSecOpsFinding.js";
import SBOMDocument from "../models/SBOMDocument.js";
import PipelineRun from "../models/PipelineRun.js";
import DevSecOpsScoreSnapshot from "../models/DevSecOpsScoreSnapshot.js";
import SecurityEvent from "../models/SecurityEvent.js";
import { runDevSecOpsScan } from "../services/devsecops/devSecOpsOrchestrator.js";
import { scanRepository } from "../services/devsecops/repositoryScanner.js";
import { runContainerScan } from "../services/devsecops/containerScanner.js";
import { generateSbom } from "../services/devsecops/sbomGenerator.js";
import { getScoreHistory } from "../services/devsecops/riskEngine.js";
import { buildCsv, buildJson, buildPdf } from "../services/devsecops/devSecOpsReportGenerator.js";
import { logSecurityEvent } from "../services/siem/siemLogger.js";

/* ============================== DASHBOARD ============================== */

export const getDashboard = async (_req, res) => {
  const [repository, findings, latestScore, history, recentEvents, sboms, pipelineRuns] = await Promise.all([
    Repository.findOne().sort({ lastScan: -1 }).lean(),
    DevSecOpsFinding.find({ status: "open" }).sort({ severity: 1, detectedAt: -1 }).lean(),
    DevSecOpsScoreSnapshot.findOne().sort({ scannedAt: -1 }).lean(),
    getScoreHistory({ days: 90 }),
    SecurityEvent.find({ category: "DEVSECOPS" }).sort({ createdAt: -1 }).limit(20).lean(),
    SBOMDocument.find().sort({ createdAt: -1 }).limit(5).select("-content").lean(),
    PipelineRun.find().sort({ createdAt: -1 }).limit(10).lean()
  ]);

  const findingsBySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  const findingsByCategory = { DEPENDENCY: 0, SECRET: 0, SAST: 0, CONTAINER: 0, IAC: 0, PIPELINE: 0 };
  for (const f of findings) {
    findingsBySeverity[f.severity] = (findingsBySeverity[f.severity] || 0) + 1;
    findingsByCategory[f.category] = (findingsByCategory[f.category] || 0) + 1;
  }

  const recommendations = findings
    .filter((f) => ["CRITICAL", "HIGH"].includes(f.severity))
    .slice(0, 10)
    .map((f) => f.recommendation)
    .filter(Boolean);

  res.json({
    overallScore: latestScore?.overallScore ?? 100,
    scores: latestScore
      ? {
          repositoryScore: latestScore.repositoryScore,
          dependencyScore: latestScore.dependencyScore,
          secretScore: latestScore.secretScore,
          containerScore: latestScore.containerScore,
          pipelineScore: latestScore.pipelineScore
        }
      : null,
    repository,
    findingCount: findings.length,
    findingsBySeverity,
    findingsByCategory,
    sboms,
    pipelineRuns,
    recentScans: recentEvents,
    trend: history,
    recommendations: [...new Set(recommendations)]
  });
};

/* ============================== REPOSITORIES ============================== */

export const listRepositories = async (_req, res) => {
  const repositories = await Repository.find().sort({ lastScan: -1 }).lean();
  res.json(repositories);
};

export const createOrRescanRepository = async (req, res) => {
  const repository = await scanRepository({ owner: req.user.id });
  res.status(201).json(repository);
};

/* ============================== DEPENDENCIES / SECRETS / SAST / CONTAINER / IAC ============================== */

function findingsListHandler(category) {
  return async (req, res) => {
    const filter = { category };
    if (req.query.severity) filter.severity = req.query.severity;
    filter.status = req.query.status || "open";
    const findings = await DevSecOpsFinding.find(filter).sort({ severity: 1, detectedAt: -1 }).limit(500).lean();
    res.json(findings);
  };
}

export const listDependencyFindings = findingsListHandler("DEPENDENCY");
export const listSecretFindings = findingsListHandler("SECRET");
export const listSastFindings = findingsListHandler("SAST");
export const listContainerFindings = findingsListHandler("CONTAINER");
export const listIacFindings = findingsListHandler("IAC");

export const runContainerScanEndpoint = async (req, res) => {
  const findings = await runContainerScan({ owner: req.user.id });
  res.status(201).json(findings);
};

/* ============================== SBOM ============================== */

export const listSboms = async (_req, res) => {
  const sboms = await SBOMDocument.find().sort({ createdAt: -1 }).select("-content").lean();
  res.json(sboms);
};

export const generateSbomEndpoint = async (req, res) => {
  const { format = "CycloneDX", serialization = "JSON" } = req.body || {};
  const sbom = await generateSbom({ owner: req.user.id, format, serialization });
  res.status(201).json(sbom);
};

/* ============================== REPORTS ============================== */

export const listReports = async (_req, res) => {
  const reports = await SBOMDocument.find().sort({ createdAt: -1 }).limit(20).select("-content").lean();
  res.json(reports);
};

/* ============================== SCAN ============================== */

export const runScan = async (req, res) => {
  const result = await runDevSecOpsScan({ owner: req.user.id, checkLiveDependencies: req.query.live !== "false" });
  res.json(result);
};

/* ============================== EXPORT ============================== */

export const exportReport = async (req, res) => {
  const format = (req.params.format || req.query.format || "json").toUpperCase();
  const reportType = req.query.reportType || "executive";

  const [repository, findings, latestScore, trend, sboms, pipelineRuns] = await Promise.all([
    Repository.findOne().sort({ lastScan: -1 }).lean(),
    DevSecOpsFinding.find({ status: "open" }).sort({ severity: 1, detectedAt: -1 }).lean(),
    DevSecOpsScoreSnapshot.findOne().sort({ scannedAt: -1 }).lean(),
    getScoreHistory({ days: 90 }),
    SBOMDocument.find().sort({ createdAt: -1 }).limit(5).lean(),
    PipelineRun.find().sort({ createdAt: -1 }).limit(10).lean()
  ]);

  const generatedAt = new Date();
  const filename = `devsecops-${reportType}-report-${Date.now()}.${format.toLowerCase()}`;
  const overallScore = latestScore?.overallScore ?? 100;
  const scores = latestScore
    ? {
        repositoryScore: latestScore.repositoryScore,
        dependencyScore: latestScore.dependencyScore,
        secretScore: latestScore.secretScore,
        containerScore: latestScore.containerScore,
        pipelineScore: latestScore.pipelineScore
      }
    : null;

  await logSecurityEvent({
    owner: req.user.id,
    type: "devsecops_scan",
    message: `DevSecOps ${reportType} report generated (${format})`,
    metadata: { format, reportType, overallScore }
  });

  const payload = { repository, findings, overallScore, scores, sbom: sboms, pipelineRuns, trend, generatedAt, reportType };

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
