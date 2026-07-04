/**
 * Phase 12 (DevSecOps/Supply Chain) - PART 1: self-scans the git repository this code actually
 * lives in via read-only `git` commands (no GitHub/GitLab/Azure DevOps/Bitbucket API token
 * required) - mirrors services/cloud/assetDiscovery.js's "introspect what's actually here" idiom.
 */
import { execFileSync } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import Repository from "../../models/Repository.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, "..", "..", "..");

const HIGH_RISK_THRESHOLD = 70;

function git(args) {
  try {
    return execFileSync("git", args, { cwd: REPO_ROOT, encoding: "utf8", timeout: 5000 }).trim();
  } catch {
    return "";
  }
}

/** Detects the provider from a git remote URL's host - github.com/gitlab.com/dev.azure.com/
 *  bitbucket.org - never assumes GitHub by default so a non-GitHub remote is reported honestly. */
export function detectProvider(remoteUrl) {
  if (!remoteUrl) return "Unknown";
  if (/github\.com/.test(remoteUrl)) return "GitHub";
  if (/gitlab\.com/.test(remoteUrl)) return "GitLab";
  if (/dev\.azure\.com|visualstudio\.com/.test(remoteUrl)) return "AzureDevOps";
  if (/bitbucket\.org/.test(remoteUrl)) return "Bitbucket";
  return "Unknown";
}

export function extractRepoName(remoteUrl) {
  if (!remoteUrl) return "local-repository";
  const match = /[/:]([^/]+\/[^/]+?)(\.git)?$/.exec(remoteUrl.trim());
  return match ? match[1] : remoteUrl;
}

export function readGitInfo() {
  const remoteLine = git(["remote", "-v"]).split("\n")[0] || "";
  const remoteUrl = remoteLine.split(/\s+/)[1] || "";
  const branch = git(["branch", "--show-current"]) || "unknown";
  const commit = git(["rev-parse", "HEAD"]) || "";
  const ownerName = git(["log", "-1", "--format=%an"]) || "unknown";
  return { remoteUrl, branch, commit, ownerName };
}

export async function scanRepository({ owner } = {}) {
  const { remoteUrl, branch, commit, ownerName } = readGitInfo();
  const provider = detectProvider(remoteUrl);
  const name = extractRepoName(remoteUrl);

  const existing = await Repository.findOne({ name });
  const repo = await Repository.findOneAndUpdate(
    { name },
    {
      name,
      provider,
      remoteUrl,
      defaultBranch: branch || "main",
      branch,
      commit,
      ownerName,
      visibility: provider === "Unknown" ? "unknown" : "public",
      lastScan: new Date()
    },
    { upsert: true, new: true }
  );

  if (repo.riskScore >= HIGH_RISK_THRESHOLD) {
    await logSecurityEvent({
      owner,
      type: "high_risk_repository",
      message: `Repository "${name}" is at high risk (score ${repo.riskScore})`,
      metadata: { repositoryId: String(repo._id), riskScore: repo.riskScore }
    }).catch(() => {});
  } else if (!existing) {
    await logSecurityEvent({
      owner,
      type: "devsecops_scan",
      message: `Repository "${name}" discovered and tracked`,
      metadata: { repositoryId: String(repo._id), provider }
    }).catch(() => {});
  }

  return repo;
}

export { REPO_ROOT };
