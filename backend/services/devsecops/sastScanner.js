/**
 * Phase 12 (DevSecOps/Supply Chain) - PART 4: pattern-based static analysis over this repo's own
 * backend/frontend source. Each rule is a small pure function `(filePath, content) => finding[]`,
 * mirroring services/cloud/configScanner.js's rule-function convention so every rule is
 * independently unit-testable without touching the filesystem or DB in tests.
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import DevSecOpsFinding from "../../models/DevSecOpsFinding.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, "..", "..", "..");
const EXCLUDED_DIRS = new Set(["node_modules", ".git", ".next", "uploads", "keys", "dist", "build", ".turbo", "tests"]);
const SCANNABLE_EXTENSIONS = new Set([".js", ".jsx", ".ts", ".tsx"]);

function lineOf(content, index) {
  return content.slice(0, index).split("\n").length;
}

function findAll(content, pattern) {
  const matches = [];
  const re = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
  let m;
  while ((m = re.exec(content))) matches.push({ index: m.index, match: m[0] });
  return matches;
}

export const SAST_RULES = [
  {
    id: "sql-injection-concat",
    title: "Possible SQL Injection via String Concatenation",
    severity: "HIGH",
    pattern: /(SELECT|INSERT|UPDATE|DELETE)[^;`'"]*\+\s*(req\.|\w+Id\b)/i,
    recommendation: "Use parameterized queries/prepared statements instead of concatenating user input into SQL."
  },
  {
    id: "command-injection",
    title: "Possible Command Injection",
    severity: "CRITICAL",
    pattern: /child_process\.(exec|execSync)\(\s*(`[^`]*\$\{|[^,)]*\+\s*req\.)/,
    recommendation: "Use execFile/execFileSync with an argument array instead of exec()/execSync() with interpolated input."
  },
  {
    id: "eval-usage",
    title: "Use of eval()",
    severity: "HIGH",
    pattern: /\beval\(/,
    recommendation: "Avoid eval() - it can execute arbitrary code if any part of its input is influenced by user data."
  },
  {
    id: "open-redirect",
    title: "Possible Open Redirect",
    severity: "MEDIUM",
    pattern: /res\.redirect\(\s*req\.(query|params|body)/,
    recommendation: "Validate/allowlist redirect targets instead of redirecting directly to a user-supplied URL."
  },
  {
    id: "path-traversal",
    title: "Possible Path Traversal",
    severity: "HIGH",
    pattern: /path\.join\([^)]*req\.(params|query|body)/,
    recommendation: "Validate and normalize any user-supplied path segment, and confirm the resolved path stays within the intended base directory."
  },
  {
    id: "weak-crypto-hash",
    title: "Weak Hash Algorithm (MD5/SHA1) Used for a Security-Sensitive Purpose",
    severity: "MEDIUM",
    pattern: /createHash\((["'])(md5|sha1)\1\)/i,
    recommendation: "Use SHA-256 or stronger for any integrity/security-relevant hash; MD5/SHA1 are only acceptable for legacy interoperability, never as a security control.",
    excludeFiles: ["utils/fileHashes.js"]
  },
  {
    id: "insecure-jwt-no-expiry",
    title: "JWT Signed Without an Expiration",
    severity: "MEDIUM",
    pattern: /jwt\.sign\(/,
    recommendation: "Always pass an `expiresIn` option to jwt.sign() so tokens are not valid indefinitely.",
    requireAbsence: /expiresIn/
  },
  {
    id: "ssrf-fetch-user-input",
    title: "Possible SSRF via Unvalidated Outbound Request URL",
    severity: "HIGH",
    pattern: /fetch\(\s*req\.(query|params|body)/,
    recommendation: "Validate/allowlist any URL built from user input before making an outbound request."
  },
  {
    id: "unsafe-file-upload-no-limit",
    title: "File Upload Without a Size Limit",
    severity: "MEDIUM",
    pattern: /multer\(\s*\)/,
    recommendation: "Configure multer({ limits: { fileSize } }) to bound upload size."
  },
  {
    id: "xxe-xml-parse",
    title: "Possible XXE (XML Parsing With External Entities Enabled)",
    severity: "HIGH",
    pattern: /new\s+DOMParser\(\)|libxmljs\.parseXml\(/,
    recommendation: "Disable external entity resolution when parsing untrusted XML."
  }
];

function fileHasRule(relativePath, rule, content) {
  if (rule.excludeFiles?.some((excluded) => relativePath.endsWith(excluded))) return [];
  const matches = findAll(content, rule.pattern);
  if (rule.requireAbsence) {
    return matches.filter((m) => {
      const windowEnd = Math.min(content.length, m.index + 200);
      return !rule.requireAbsence.test(content.slice(m.index, windowEnd));
    });
  }
  return matches;
}

/** Pure: scans one file's text content against every SAST rule, returns findings. */
export function scanFileForSast(relativePath, content) {
  const findings = [];
  for (const rule of SAST_RULES) {
    for (const m of fileHasRule(relativePath, rule, content)) {
      findings.push({
        ruleId: `sast:${rule.id}`,
        title: rule.title,
        severity: rule.severity,
        file: relativePath,
        line: lineOf(content, m.index),
        recommendation: rule.recommendation
      });
    }
  }
  return findings;
}

function walkFiles(dir) {
  const results = [];
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }
  for (const entry of entries) {
    if (EXCLUDED_DIRS.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) results.push(...walkFiles(fullPath));
    else if (SCANNABLE_EXTENSIONS.has(path.extname(entry.name))) results.push(fullPath);
  }
  return results;
}

export async function runSastScan({ owner } = {}) {
  const files = walkFiles(REPO_ROOT);
  const allFindings = [];

  for (const filePath of files) {
    const relativePath = path.relative(REPO_ROOT, filePath).replace(/\\/g, "/");
    // The DevSecOps scanner modules themselves describe what they detect in prose (rule titles/
    // recommendations, e.g. "Use of eval()") - scanning their own source would trivially self-
    // match on that descriptive text, not an actual vulnerability.
    if (relativePath.startsWith("backend/services/devsecops/")) continue;

    let content;
    try {
      content = fs.readFileSync(filePath, "utf8");
    } catch {
      continue;
    }
    allFindings.push(...scanFileForSast(relativePath, content).map((f) => ({ ...f, category: "SAST" })));
  }

  const persisted = [];
  const seenKeys = new Set();

  for (const finding of allFindings) {
    seenKeys.add(`${finding.ruleId}:${finding.file}:${finding.line}`);
    const existing = await DevSecOpsFinding.findOne({ ruleId: finding.ruleId, file: finding.file, line: finding.line, category: "SAST", status: "open" });
    if (existing) {
      persisted.push(existing);
      continue;
    }
    const created = await DevSecOpsFinding.create({ ...finding, status: "open" });
    persisted.push(created);

    await logSecurityEvent({
      owner,
      type: "sast_finding",
      message: `SAST finding: ${finding.title} in ${finding.file}:${finding.line}`,
      metadata: { ruleId: finding.ruleId, severity: finding.severity, file: finding.file }
    }).catch(() => {});
  }

  return persisted;
}
