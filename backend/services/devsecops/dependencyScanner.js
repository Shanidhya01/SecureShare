/**
 * Phase 12 (DevSecOps/Supply Chain) - PART 2: scans the two real dependency manifests in this repo
 * (backend/package.json, frontend/package.json - npm is the only ecosystem actually in use here;
 * the DevSecOpsFinding.metadata.ecosystem field is free-text so pnpm/yarn/Maven/Gradle/pip/Poetry/
 * Cargo/Go Modules/NuGet projects would slot into the same schema if this repo ever gained one).
 * Local curated advisory table is consulted first (works fully offline, like
 * services/threatIntel/iocLookupService.js's local-IOC-first design); an optional live npm
 * registry "latest version" check degrades gracefully if unreachable.
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import DevSecOpsFinding from "../../models/DevSecOpsFinding.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, "..", "..", "..");
const REGISTRY_TIMEOUT_MS = 3000;

const MANIFESTS = [
  { ecosystem: "npm", dir: "backend" },
  { ecosystem: "npm", dir: "frontend" }
];

/** Curated, offline advisory table - real, well-known issues, not fabricated CVE IDs. */
const ADVISORIES = [
  {
    name: "crypto",
    severity: "HIGH",
    title: "Deprecated package shadows a Node.js builtin module",
    recommendation: "Remove the `crypto` npm dependency entirely - Node's built-in `crypto` module (already used throughout this codebase) requires no package; the npm package by this name is an abandoned no-op placeholder.",
    reference: "https://www.npmjs.com/package/crypto"
  }
];

/** Popular package names checked against for Levenshtein-distance typosquat detection. */
const POPULAR_PACKAGES = [
  "express", "react", "react-dom", "lodash", "axios", "mongoose", "jsonwebtoken", "bcrypt",
  "cors", "dotenv", "multer", "next", "chalk", "commander", "request", "moment"
];

export function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
    }
  }
  return dp[a.length][b.length];
}

/** Flags a package name as a likely typosquat only if it's close-but-not-equal to a popular name. */
export function detectTyposquat(packageName) {
  for (const popular of POPULAR_PACKAGES) {
    if (packageName === popular) return null;
    const distance = levenshtein(packageName, popular);
    if (distance > 0 && distance <= 2 && Math.abs(packageName.length - popular.length) <= 2) {
      return popular;
    }
  }
  return null;
}

function readJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}

function readInstalledLicense(dir, packageName) {
  const pkgJson = readJson(path.join(REPO_ROOT, dir, "node_modules", packageName, "package.json"));
  if (!pkgJson) return "UNKNOWN";
  if (typeof pkgJson.license === "string") return pkgJson.license;
  if (pkgJson.license?.type) return pkgJson.license.type;
  if (Array.isArray(pkgJson.licenses) && pkgJson.licenses[0]?.type) return pkgJson.licenses[0].type;
  return "UNKNOWN";
}

const COPYLEFT_LICENSES = ["GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0"];

async function checkLatestVersion(packageName) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REGISTRY_TIMEOUT_MS);
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(packageName)}/latest`, { signal: controller.signal });
    clearTimeout(timeout);
    if (!res.ok) return null;
    const data = await res.json();
    return data.version || null;
  } catch {
    return null;
  }
}

function cleanVersion(v) {
  return String(v || "").replace(/^[\^~>=<\s]+/, "");
}

function isOlderVersion(current, latest) {
  const a = cleanVersion(current).split(".").map((n) => parseInt(n, 10) || 0);
  const b = cleanVersion(latest).split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const av = a[i] || 0, bv = b[i] || 0;
    if (av < bv) return true;
    if (av > bv) return false;
  }
  return false;
}

async function scanManifest({ ecosystem, dir }, { checkLive = true } = {}) {
  const pkgJson = readJson(path.join(REPO_ROOT, dir, "package.json"));
  if (!pkgJson) return [];

  const deps = { ...(pkgJson.dependencies || {}), ...(pkgJson.devDependencies || {}) };
  const findings = [];

  for (const [name, versionRange] of Object.entries(deps)) {
    const advisory = ADVISORIES.find((a) => a.name === name);
    if (advisory) {
      findings.push({
        category: "DEPENDENCY",
        ruleId: `dependency-advisory:${name}`,
        title: advisory.title,
        severity: advisory.severity,
        package: name,
        currentVersion: versionRange,
        recommendation: advisory.recommendation,
        reference: advisory.reference,
        metadata: { ecosystem, manifest: `${dir}/package.json` }
      });
    }

    const typosquatTarget = detectTyposquat(name);
    if (typosquatTarget) {
      findings.push({
        category: "DEPENDENCY",
        ruleId: `typosquat:${name}`,
        title: `Package name "${name}" closely resembles popular package "${typosquatTarget}"`,
        severity: "MEDIUM",
        package: name,
        currentVersion: versionRange,
        recommendation: `Verify "${name}" is the intended dependency and not a typosquat of "${typosquatTarget}".`,
        reference: "https://owasp.org/www-community/attacks/Typosquatting",
        metadata: { ecosystem, manifest: `${dir}/package.json`, suspectedTarget: typosquatTarget }
      });
    }

    const license = readInstalledLicense(dir, name);
    if (COPYLEFT_LICENSES.includes(license)) {
      findings.push({
        category: "DEPENDENCY",
        ruleId: `license:${name}`,
        title: `Dependency "${name}" uses a copyleft license (${license})`,
        severity: "LOW",
        package: name,
        currentVersion: versionRange,
        recommendation: "Confirm this copyleft license is compatible with SecureShare's distribution model before shipping.",
        reference: "https://opensource.org/licenses",
        metadata: { ecosystem, manifest: `${dir}/package.json`, license }
      });
    }

    if (checkLive) {
      const latest = await checkLatestVersion(name);
      if (latest && isOlderVersion(versionRange, latest)) {
        findings.push({
          category: "DEPENDENCY",
          ruleId: `outdated:${name}`,
          title: `Dependency "${name}" is outdated`,
          severity: "LOW",
          package: name,
          currentVersion: versionRange,
          recommendedVersion: latest,
          recommendation: `Upgrade "${name}" from ${versionRange} to ${latest}.`,
          reference: `https://www.npmjs.com/package/${name}`,
          metadata: { ecosystem, manifest: `${dir}/package.json` }
        });
      }
    }
  }

  return findings;
}

export async function runDependencyScan({ owner, checkLive = true } = {}) {
  const allFindings = [];
  for (const manifest of MANIFESTS) {
    allFindings.push(...(await scanManifest(manifest, { checkLive })));
  }

  const persisted = [];
  const seenRuleIds = new Set();

  for (const finding of allFindings) {
    seenRuleIds.add(finding.ruleId);
    const existing = await DevSecOpsFinding.findOne({ ruleId: finding.ruleId, category: "DEPENDENCY", status: "open" });
    if (existing) {
      persisted.push(existing);
      continue;
    }
    const created = await DevSecOpsFinding.create({ ...finding, status: "open" });
    persisted.push(created);

    await logSecurityEvent({
      owner,
      type: "dependency_vulnerability",
      message: `Dependency finding: ${finding.title}`,
      metadata: { ruleId: finding.ruleId, severity: finding.severity, package: finding.package }
    }).catch(() => {});
  }

  await DevSecOpsFinding.updateMany(
    { category: "DEPENDENCY", status: "open", ruleId: { $nin: [...seenRuleIds] } },
    { status: "resolved", resolvedAt: new Date() }
  );

  return persisted;
}
