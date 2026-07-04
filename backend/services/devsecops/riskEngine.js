/**
 * Phase 12 (DevSecOps/Supply Chain) - PART 10: computes the 5 component scores the spec names
 * (Repository, Dependency, Secret, Container, Pipeline) plus a weighted overall DevSecOps score -
 * mirrors services/cloud/scoreEngine.js's severity-weight table approach. SAST findings roll into
 * repositoryScore (source-code-level, tied to the repo) and IaC findings roll into containerScore
 * (docker-compose config sits alongside the Dockerfile it deploys) rather than adding two more
 * top-level scores beyond the 5 the spec explicitly lists.
 */
import Repository from "../../models/Repository.js";
import DevSecOpsFinding from "../../models/DevSecOpsFinding.js";
import PipelineRun from "../../models/PipelineRun.js";
import DevSecOpsScoreSnapshot from "../../models/DevSecOpsScoreSnapshot.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

const SEVERITY_WEIGHT = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3, INFO: 1 };

function clampScore(n) {
  return Math.max(0, Math.min(100, Math.round(n)));
}

function scoreFromOpenFindings(findings) {
  if (findings.length === 0) return 100;
  const penalty = findings.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] ?? SEVERITY_WEIGHT.MEDIUM), 0);
  return clampScore(100 - penalty);
}

async function computeRepositoryScore() {
  const [repos, sastFindings] = await Promise.all([
    Repository.find().select("riskScore").lean(),
    DevSecOpsFinding.find({ category: "SAST", status: "open" }).select("severity").lean()
  ]);
  const repoAvg = repos.length ? repos.reduce((sum, r) => sum + (r.riskScore || 0), 0) / repos.length : 0;
  const sastScore = scoreFromOpenFindings(sastFindings);
  return clampScore((100 - repoAvg) * 0.4 + sastScore * 0.6);
}

async function computeDependencyScore() {
  const findings = await DevSecOpsFinding.find({ category: "DEPENDENCY", status: "open" }).select("severity").lean();
  return scoreFromOpenFindings(findings);
}

async function computeSecretScore() {
  const findings = await DevSecOpsFinding.find({ category: "SECRET", status: "open" }).select("severity").lean();
  return scoreFromOpenFindings(findings);
}

async function computeContainerScore() {
  const [containerFindings, iacFindings] = await Promise.all([
    DevSecOpsFinding.find({ category: "CONTAINER", status: "open" }).select("severity").lean(),
    DevSecOpsFinding.find({ category: "IAC", status: "open" }).select("severity").lean()
  ]);
  return clampScore((scoreFromOpenFindings(containerFindings) + scoreFromOpenFindings(iacFindings)) / 2);
}

async function computePipelineScore() {
  const [pipelineFindings, recentRuns] = await Promise.all([
    DevSecOpsFinding.find({ category: "PIPELINE", status: "open" }).select("severity").lean(),
    PipelineRun.find().sort({ createdAt: -1 }).limit(10).select("status").lean()
  ]);
  const findingScore = scoreFromOpenFindings(pipelineFindings);
  if (recentRuns.length === 0) return findingScore;
  const failedRatio = recentRuns.filter((r) => r.status === "failed" || r.status === "blocked").length / recentRuns.length;
  return clampScore(findingScore * (1 - failedRatio * 0.5));
}

const WEIGHTS = { repositoryScore: 0.25, dependencyScore: 0.25, secretScore: 0.2, containerScore: 0.2, pipelineScore: 0.1 };

export function computeOverallScore(scores) {
  return clampScore(Object.entries(WEIGHTS).reduce((sum, [key, weight]) => sum + (scores[key] ?? 100) * weight, 0));
}

const SCORE_DROP_THRESHOLD = 70;

export async function runRiskEngine({ owner } = {}) {
  const [repositoryScore, dependencyScore, secretScore, containerScore, pipelineScore] = await Promise.all([
    computeRepositoryScore(),
    computeDependencyScore(),
    computeSecretScore(),
    computeContainerScore(),
    computePipelineScore()
  ]);

  const scores = { repositoryScore, dependencyScore, secretScore, containerScore, pipelineScore };
  const overallScore = computeOverallScore(scores);

  const snapshot = await DevSecOpsScoreSnapshot.create({ ...scores, overallScore, scannedAt: new Date() });

  await logSecurityEvent({
    owner,
    type: "devsecops_risk_updated",
    message: `DevSecOps risk posture recomputed (overall score ${overallScore})`,
    metadata: { ...scores, overallScore, scoreDropped: overallScore < SCORE_DROP_THRESHOLD }
  }).catch(() => {});

  return { ...scores, overallScore, snapshotId: snapshot._id };
}

export async function getScoreHistory({ days = 90 } = {}) {
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  return DevSecOpsScoreSnapshot.find({ scannedAt: { $gte: since } }).sort({ scannedAt: 1 }).lean();
}
