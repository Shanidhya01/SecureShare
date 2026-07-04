/**
 * Phase 12 (DevSecOps/Supply Chain) - PART 8: detects CI/CD pipeline configuration in this repo.
 * No `.github/workflows` exists here today, so that absence is reported as a real, honest finding
 * rather than synthesizing fake pipeline runs. If GITHUB_TOKEN + GITHUB_REPO are configured, one
 * real GitHub Actions API call fetches the latest workflow run - degrading gracefully otherwise,
 * same shape as services/threatIntel/providers/*'s optional-API-key pattern.
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import DevSecOpsFinding from "../../models/DevSecOpsFinding.js";
import PipelineRun from "../../models/PipelineRun.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, "..", "..", "..");
const API_TIMEOUT_MS = 4000;

export function detectCiConfig() {
  const ghWorkflowsDir = path.join(REPO_ROOT, ".github", "workflows");
  const hasGithubActions = fs.existsSync(ghWorkflowsDir) && fs.readdirSync(ghWorkflowsDir).some((f) => /\.ya?ml$/.test(f));
  const hasGitlabCi = fs.existsSync(path.join(REPO_ROOT, ".gitlab-ci.yml"));
  const hasJenkins = fs.existsSync(path.join(REPO_ROOT, "Jenkinsfile"));
  const hasAzurePipelines = fs.existsSync(path.join(REPO_ROOT, "azure-pipelines.yml"));

  return { hasGithubActions, hasGitlabCi, hasJenkins, hasAzurePipelines };
}

async function fetchLatestGithubRun(repo, token) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
    const res = await fetch(`https://api.github.com/repos/${repo}/actions/runs?per_page=1`, {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json" },
      signal: controller.signal
    });
    clearTimeout(timeout);
    if (!res.ok) return null;
    const data = await res.json();
    return data.workflow_runs?.[0] || null;
  } catch {
    return null;
  }
}

export async function runPipelineMonitor({ owner } = {}) {
  const config = detectCiConfig();
  const findings = [];
  let pipelineRun = null;

  const anyCiDetected = config.hasGithubActions || config.hasGitlabCi || config.hasJenkins || config.hasAzurePipelines;

  if (!anyCiDetected) {
    findings.push({
      category: "PIPELINE",
      ruleId: "pipeline:no-ci-config",
      title: "No CI/CD Pipeline Configuration Detected",
      severity: "MEDIUM",
      recommendation: "Add a CI/CD pipeline (GitHub Actions, GitLab CI, Jenkins, or Azure Pipelines) with automated tests and a security gate before merging to the default branch.",
      reference: "https://docs.github.com/actions"
    });

    pipelineRun = await PipelineRun.create({
      provider: "None",
      name: "No pipeline configured",
      status: "unknown",
      source: "detected"
    });
  } else if (config.hasGithubActions && process.env.GITHUB_TOKEN && process.env.GITHUB_REPO) {
    const run = await fetchLatestGithubRun(process.env.GITHUB_REPO, process.env.GITHUB_TOKEN);
    if (run) {
      const status = run.conclusion === "success" ? "success" : run.conclusion === "failure" ? "failed" : "unknown";
      pipelineRun = await PipelineRun.create({
        provider: "GitHubActions",
        name: run.name || "workflow",
        status,
        branch: run.head_branch,
        commit: run.head_sha,
        startedAt: run.run_started_at ? new Date(run.run_started_at) : undefined,
        finishedAt: run.updated_at ? new Date(run.updated_at) : undefined,
        source: "live"
      });

      if (status === "failed") {
        await logSecurityEvent({ owner, type: "pipeline_failed", message: `GitHub Actions run "${pipelineRun.name}" failed`, metadata: { runId: run.id } }).catch(() => {});
      }
    }
  } else if (config.hasGithubActions) {
    pipelineRun = await PipelineRun.create({ provider: "GitHubActions", name: "GitHub Actions workflow(s) detected", status: "unknown", source: "detected" });
  }

  const persisted = [];
  for (const finding of findings) {
    const existing = await DevSecOpsFinding.findOne({ ruleId: finding.ruleId, category: "PIPELINE", status: "open" });
    if (existing) {
      persisted.push(existing);
      continue;
    }
    const created = await DevSecOpsFinding.create({ ...finding, status: "open" });
    persisted.push(created);
    await logSecurityEvent({ owner, type: "devsecops_scan", message: `Pipeline finding: ${finding.title}`, metadata: { ruleId: finding.ruleId, category: "PIPELINE" } }).catch(() => {});
  }

  if (anyCiDetected) {
    await DevSecOpsFinding.updateMany(
      { category: "PIPELINE", ruleId: "pipeline:no-ci-config", status: "open" },
      { status: "resolved", resolvedAt: new Date() }
    );
  }

  return { findings: persisted, pipelineRun, config };
}
