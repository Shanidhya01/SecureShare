/**
 * Phase 12 (DevSecOps/Supply Chain) - PART 3: regex + entropy secret detection over this repo's
 * own tracked source files. Read-only, local-only - never uploads matched values anywhere; only
 * a masked preview and rule metadata are ever persisted (same masking discipline DLP's detectors
 * already use for matched secret previews).
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import DevSecOpsFinding from "../../models/DevSecOpsFinding.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, "..", "..", "..");

// "tests" is excluded because Phase 5 (DLP)'s own test suite deliberately contains fake
// "AKIA...EXAMPLE"-style AWS keys and dummy PEM blocks as detector test fixtures - flagging those
// as real secrets would be pure noise, the same self-matching problem excluded for SAST above.
const EXCLUDED_DIRS = new Set(["node_modules", ".git", ".next", "uploads", "keys", "dist", "build", ".turbo", "tests"]);
// Lockfiles are generated artifacts full of hashes/URLs/binary-target names that read as
// high-entropy strings but are never secrets - excluded by filename rather than extension.
const EXCLUDED_FILENAMES = new Set(["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]);
// The generic entropy heuristic is restricted to actual code/config files - markdown docs
// legitimately contain example IDs/hex snippets (e.g. a sample MongoDB ObjectId) that read as
// high-entropy without being secrets; the vendor-specific regex rules above still run on markdown.
const ENTROPY_SCAN_EXTENSIONS = new Set([".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml"]);
// Deliberately excludes .env/.env.example/.env.production: real .env holds this deployment's
// actual live secrets (scanning it would mean persisting a masked preview of a real production
// secret into the findings collection - a worse exposure surface than not scanning it at all),
// and .env.example is a placeholder template whose PEM/key blocks would otherwise false-positive
// against the private-key rule below. Source code is where an *accidentally hardcoded* secret
// would actually show up - which is what this scanner targets.
const SCANNABLE_EXTENSIONS = new Set([".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml", ".md"]);

/** Built-in rules. `customRules` (extensible - satisfies "Custom Rules") may be passed in by callers. */
export const SECRET_RULES = [
  { id: "aws-access-key", title: "AWS Access Key ID", severity: "CRITICAL", pattern: /AKIA[0-9A-Z]{16}/g },
  { id: "aws-secret-key", title: "AWS Secret Access Key", severity: "CRITICAL", pattern: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g, requireContextKeyword: /aws|secret/i },
  { id: "azure-key", title: "Azure Storage/Service Key", severity: "CRITICAL", pattern: /AccountKey=[A-Za-z0-9+/=]{80,}/g },
  { id: "gcp-key", title: "GCP Service Account Key", severity: "CRITICAL", pattern: /"type":\s*"service_account"/g },
  { id: "github-token", title: "GitHub Token", severity: "CRITICAL", pattern: /gh[pousr]_[A-Za-z0-9]{36,}/g },
  { id: "gitlab-token", title: "GitLab Token", severity: "CRITICAL", pattern: /glpat-[A-Za-z0-9_-]{20,}/g },
  { id: "slack-token", title: "Slack Token", severity: "HIGH", pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/g },
  { id: "stripe-key", title: "Stripe API Key", severity: "CRITICAL", pattern: /sk_(live|test)_[A-Za-z0-9]{16,}/g },
  { id: "openai-key", title: "OpenAI API Key", severity: "CRITICAL", pattern: /sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{32,}/g },
  { id: "private-key", title: "Private Key (PEM)", severity: "CRITICAL", pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { id: "ssh-key", title: "SSH Private Key", severity: "CRITICAL", pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g },
  { id: "jwt-token", title: "JWT Token (hardcoded)", severity: "MEDIUM", pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { id: "db-password", title: "Database Connection String with Credentials", severity: "HIGH", pattern: /(mongodb(\+srv)?|postgres|mysql):\/\/[^:\s]+:[^@\s]+@/g },
  { id: "generic-api-key", title: "Generic API Key Assignment", severity: "MEDIUM", pattern: /(api[_-]?key|apikey)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']/gi },
  { id: "oauth-secret", title: "OAuth Client Secret Assignment", severity: "HIGH", pattern: /(client[_-]?secret)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']/gi }
];

/** Shannon entropy of a string, in bits/char - high values (>4.0) alongside a length threshold
 *  flag arbitrary high-entropy tokens that don't match a specific vendor pattern above. */
export function shannonEntropy(value) {
  if (!value) return 0;
  const freq = {};
  for (const ch of value) freq[ch] = (freq[ch] || 0) + 1;
  return Object.values(freq).reduce((sum, count) => {
    const p = count / value.length;
    return sum - p * Math.log2(p);
  }, 0);
}

const HIGH_ENTROPY_TOKEN_RE = /["'`]([A-Za-z0-9+/_-]{24,})["'`]/g;
const ENTROPY_THRESHOLD = 4.2;

function maskValue(value) {
  if (value.length <= 8) return "***";
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
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
    if (entry.isDirectory()) {
      results.push(...walkFiles(fullPath));
    } else if (!EXCLUDED_FILENAMES.has(entry.name) && SCANNABLE_EXTENSIONS.has(path.extname(entry.name))) {
      results.push(fullPath);
    }
  }
  return results;
}

/** Pure: scans one file's text content, returns findings (no fs/db access). `checkEntropy`
 *  defaults on but is disabled by the caller for file types (e.g. markdown) where the generic
 *  high-entropy heuristic is known to false-positive on legitimate example data. */
export function scanFileContent(relativePath, content, customRules = [], { checkEntropy = true } = {}) {
  const findings = [];
  const rules = [...SECRET_RULES, ...customRules];

  for (const rule of rules) {
    const pattern = new RegExp(rule.pattern.source, rule.pattern.flags.includes("g") ? rule.pattern.flags : `${rule.pattern.flags}g`);
    let match;
    while ((match = pattern.exec(content))) {
      if (rule.requireContextKeyword) {
        const windowStart = Math.max(0, match.index - 60);
        const window = content.slice(windowStart, match.index);
        if (!rule.requireContextKeyword.test(window)) continue;
      }
      const line = content.slice(0, match.index).split("\n").length;
      findings.push({
        ruleId: `secret:${rule.id}`,
        title: rule.title,
        severity: rule.severity,
        file: relativePath,
        line,
        metadata: { preview: maskValue(match[0]) }
      });
    }
  }

  let entropyMatch;
  HIGH_ENTROPY_TOKEN_RE.lastIndex = 0;
  while (checkEntropy && (entropyMatch = HIGH_ENTROPY_TOKEN_RE.exec(content))) {
    const token = entropyMatch[1];
    if (shannonEntropy(token) >= ENTROPY_THRESHOLD) {
      const line = content.slice(0, entropyMatch.index).split("\n").length;
      findings.push({
        ruleId: "secret:high-entropy-string",
        title: "High-Entropy String (possible secret)",
        severity: "LOW",
        file: relativePath,
        line,
        metadata: { preview: maskValue(token), entropy: Number(shannonEntropy(token).toFixed(2)) }
      });
    }
  }

  return findings;
}

export async function runSecretScan({ owner, customRules = [] } = {}) {
  const files = walkFiles(REPO_ROOT);
  const allFindings = [];

  for (const filePath of files) {
    let content;
    try {
      content = fs.readFileSync(filePath, "utf8");
    } catch {
      continue;
    }
    const relativePath = path.relative(REPO_ROOT, filePath).replace(/\\/g, "/");
    // Same self-matching problem as sastScanner.js's exclusion: this module's own rule patterns
    // literally contain the marker strings (e.g. "-----BEGIN ... PRIVATE KEY-----") they detect.
    if (relativePath.startsWith("backend/services/devsecops/")) continue;
    const checkEntropy = ENTROPY_SCAN_EXTENSIONS.has(path.extname(filePath));
    allFindings.push(...scanFileContent(relativePath, content, customRules, { checkEntropy }).map((f) => ({ ...f, category: "SECRET" })));
  }

  const persisted = [];
  const seenKeys = new Set();

  for (const finding of allFindings) {
    const key = `${finding.ruleId}:${finding.file}:${finding.line}`;
    seenKeys.add(key);
    const existing = await DevSecOpsFinding.findOne({ ruleId: finding.ruleId, file: finding.file, line: finding.line, category: "SECRET", status: "open" });
    if (existing) {
      persisted.push(existing);
      continue;
    }
    const created = await DevSecOpsFinding.create({ ...finding, status: "open" });
    persisted.push(created);

    await logSecurityEvent({
      owner,
      type: "secret_found",
      message: `Secret finding: ${finding.title} in ${finding.file}:${finding.line}`,
      metadata: { ruleId: finding.ruleId, severity: finding.severity, file: finding.file }
    }).catch(() => {});
  }

  return persisted;
}
