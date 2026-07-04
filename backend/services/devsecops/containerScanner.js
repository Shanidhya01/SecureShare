/**
 * Phase 12 (DevSecOps/Supply Chain) - PART 5: static analysis of this repo's own
 * backend/Dockerfile - no live container registry/CVE feed, no image needs to be built or pulled.
 * Rules mirror services/cloud/configScanner.js's pure-rule convention.
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import DevSecOpsFinding from "../../models/DevSecOpsFinding.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, "..", "..", "..");
const DOCKERFILE_PATH = path.join(REPO_ROOT, "backend", "Dockerfile");

/** Base image tags known to be old/EOL - a short curated list, not a live registry feed. */
const OUTDATED_BASE_IMAGES = [
  { pattern: /node:1[0-6](\D|$)/, title: "Base image uses an end-of-life Node.js major version" },
  { pattern: /node:[\d.]+-alpine3\.1[0-2]\b/, title: "Base image uses an outdated Alpine minor version" },
  { pattern: /:latest\b/, title: "Base image uses the mutable \":latest\" tag instead of a pinned version" }
];

export function parseDockerfile(content) {
  const lines = content.split("\n");
  const findings = [];

  const fromLine = lines.findIndex((l) => /^\s*FROM\s+/i.test(l));
  const fromMatch = fromLine >= 0 ? /^\s*FROM\s+(\S+)/i.exec(lines[fromLine]) : null;
  const baseImage = fromMatch ? fromMatch[1] : null;

  if (baseImage) {
    for (const advisory of OUTDATED_BASE_IMAGES) {
      if (advisory.pattern.test(baseImage)) {
        findings.push({
          ruleId: `container:base-image:${advisory.title}`,
          title: advisory.title,
          severity: "MEDIUM",
          line: fromLine + 1,
          recommendation: "Pin to a specific, currently-supported base image version/digest.",
          metadata: { baseImage }
        });
      }
    }
  }

  const hasUser = lines.some((l) => /^\s*USER\s+/i.test(l));
  if (!hasUser) {
    findings.push({
      ruleId: "container:running-as-root",
      title: "Container Runs as Root (no USER directive)",
      severity: "HIGH",
      recommendation: "Add a non-root `USER` directive before the final CMD/ENTRYPOINT.",
      reference: "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user"
    });
  }

  const hasHealthcheck = lines.some((l) => /^\s*HEALTHCHECK\s+/i.test(l));
  if (!hasHealthcheck) {
    findings.push({
      ruleId: "container:missing-healthcheck",
      title: "Missing HEALTHCHECK Instruction",
      severity: "LOW",
      recommendation: "Add a HEALTHCHECK instruction so container orchestrators can detect an unhealthy instance."
    });
  }

  const cmdLine = lines.findIndex((l) => /^\s*CMD\s+/i.test(l));
  // Docker CMD is commonly written in JSON-array (exec) form - CMD ["npm", "run", "dev"] - so
  // strip punctuation before checking for the dev-server command rather than matching the shell-
  // form string "npm run dev" literally, which would never appear in exec-form syntax.
  const cmdNormalized = cmdLine >= 0 ? lines[cmdLine].replace(/["'[\],]/g, " ").replace(/\s+/g, " ") : "";
  if (cmdLine >= 0 && /\bnpm\s+run\s+dev\b|\bnodemon\b/i.test(cmdNormalized)) {
    findings.push({
      ruleId: "container:dev-server-in-production-image",
      title: "Development Server Command Used in Container Image",
      severity: "HIGH",
      line: cmdLine + 1,
      recommendation: "Use a production start command (e.g. `npm start`/`node server.js`) rather than a dev/watch server in the shipped image."
    });
  }

  const runLines = lines.filter((l) => /^\s*RUN\s+/i.test(l));
  if (runLines.some((l) => /npm install(?!\s+.*--production)/i.test(l) && !/npm ci/i.test(l))) {
    findings.push({
      ruleId: "container:non-reproducible-install",
      title: "Non-Reproducible Dependency Install (npm install instead of npm ci)",
      severity: "LOW",
      recommendation: "Use `npm ci` in container builds for a reproducible install from the lockfile."
    });
  }

  const privilegedCapabilities = lines.filter((l) => /--cap-add|--privileged/i.test(l));
  if (privilegedCapabilities.length > 0) {
    findings.push({
      ruleId: "container:dangerous-capabilities",
      title: "Dangerous Linux Capabilities Requested",
      severity: "HIGH",
      recommendation: "Remove --privileged/--cap-add unless the specific capability is strictly required."
    });
  }

  const exposeLines = lines.filter((l) => /^\s*EXPOSE\s+/i.test(l));
  const exposedPorts = exposeLines.flatMap((l) => (/^\s*EXPOSE\s+(.+)/i.exec(l)?.[1] || "").split(/\s+/).filter(Boolean));

  return { findings, baseImage, exposedPorts };
}

export async function runContainerScan({ owner } = {}) {
  let content;
  try {
    content = fs.readFileSync(DOCKERFILE_PATH, "utf8");
  } catch {
    return [];
  }

  const { findings: rawFindings, exposedPorts } = parseDockerfile(content);
  const findings = rawFindings.map((f) => ({ ...f, category: "CONTAINER", file: "backend/Dockerfile", metadata: { ...(f.metadata || {}), exposedPorts } }));

  const persisted = [];
  const seenRuleIds = new Set();

  for (const finding of findings) {
    seenRuleIds.add(finding.ruleId);
    const existing = await DevSecOpsFinding.findOne({ ruleId: finding.ruleId, category: "CONTAINER", status: "open" });
    if (existing) {
      persisted.push(existing);
      continue;
    }
    const created = await DevSecOpsFinding.create({ ...finding, status: "open" });
    persisted.push(created);

    await logSecurityEvent({
      owner,
      type: "container_vulnerability",
      message: `Container finding: ${finding.title}`,
      metadata: { ruleId: finding.ruleId, severity: finding.severity }
    }).catch(() => {});
  }

  await DevSecOpsFinding.updateMany(
    { category: "CONTAINER", status: "open", ruleId: { $nin: [...seenRuleIds] } },
    { status: "resolved", resolvedAt: new Date() }
  );

  return persisted;
}
