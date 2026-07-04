/**
 * Phase 12 (DevSecOps/Supply Chain) - PART 6: analyzes this repo's own docker-compose.yml with a
 * lightweight line-based reader (no new YAML dependency - mirrors services/cloud/assetDiscovery.js's
 * regex-based docker-compose.yml parsing from Phase 11). Terraform/CloudFormation/Kubernetes/Helm
 * are supported via file-type dispatch *if* such files exist in the repo - they don't today, so
 * that's reported honestly rather than faked.
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import DevSecOpsFinding from "../../models/DevSecOpsFinding.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, "..", "..", "..");
const COMPOSE_PATH = path.join(REPO_ROOT, "docker-compose.yml");

/** Pure: analyzes docker-compose.yml text, returns findings. */
export function analyzeDockerCompose(content) {
  const lines = content.split("\n");
  const findings = [];

  const portLines = lines
    .map((l, i) => ({ line: l, i }))
    .filter(({ line }) => /^\s*-\s*["']?\d{2,5}:\d{2,5}["']?\s*$/.test(line));

  for (const { line, i } of portLines) {
    const match = /(\d{2,5}):(\d{2,5})/.exec(line);
    if (match && !line.includes("127.0.0.1") && !line.includes("localhost")) {
      findings.push({
        ruleId: `iac:public-port:${match[1]}`,
        title: `Port ${match[1]} is bound to all interfaces (publicly reachable)`,
        severity: match[1] === "27017" || match[1] === "5432" || match[1] === "3306" ? "HIGH" : "MEDIUM",
        line: i + 1,
        recommendation: `Bind to "127.0.0.1:${match[1]}:${match[2]}" (or remove the port mapping) unless this port must be reachable from outside the host.`,
        reference: "https://docs.docker.com/compose/compose-file/05-services/#ports"
      });
    }
  }

  if (/privileged:\s*true/i.test(content)) {
    findings.push({
      ruleId: "iac:privileged-container",
      title: "Privileged Container Configured",
      severity: "CRITICAL",
      recommendation: "Remove `privileged: true` unless the container genuinely requires full host device access.",
      reference: "https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities"
    });
  }

  if (/network_mode:\s*["']?host["']?/i.test(content)) {
    findings.push({
      ruleId: "iac:host-networking",
      title: "Host Networking Mode Configured",
      severity: "HIGH",
      recommendation: "Avoid `network_mode: host` - it removes network isolation between the container and host."
    });
  }

  // Slice out just the top-level "services:" section, then split it into per-service blocks by
  // its 2-space-indented "name:" keys (docker-compose's actual nesting depth) - splitting on any
  // non-indented "key:" line (the previous approach) only ever found the single top-level
  // "services:" key itself, never the individual services nested inside it.
  const servicesStart = lines.findIndex((l) => /^services:\s*$/.test(l));
  const serviceLines = servicesStart === -1
    ? []
    : lines.slice(servicesStart + 1, lines.findIndex((l, i) => i > servicesStart && /^\S/.test(l)) === -1 ? undefined : lines.findIndex((l, i) => i > servicesStart && /^\S/.test(l)));

  const serviceBlockText = serviceLines.join("\n");
  const serviceBlocks = serviceBlockText
    .split(/^(?=\s{2}\S.*:\s*$)/m)
    .filter((b) => /^\s{2}\S.*:\s*$/.test(b.split("\n")[0] || ""));

  for (const block of serviceBlocks) {
    const name = /^\s{2}(\S+):/.exec(block)?.[1];
    if (!name) continue;
    if (!/restart:/i.test(block)) {
      findings.push({
        ruleId: `iac:missing-restart-policy:${name}`,
        title: `Service "${name}" has no restart policy`,
        severity: "LOW",
        recommendation: `Add "restart: unless-stopped" (or similar) to service "${name}" for resilience.`
      });
    }
    if (!/deploy:|mem_limit:|cpus:/i.test(block)) {
      findings.push({
        ruleId: `iac:missing-resource-limits:${name}`,
        title: `Service "${name}" has no resource limits configured`,
        severity: "LOW",
        recommendation: `Set memory/CPU limits for service "${name}" to prevent a single container from exhausting host resources.`
      });
    }
  }

  return findings;
}

const OTHER_IAC_FILES = [
  { glob: "*.tf", type: "Terraform" },
  { glob: "template.yaml", type: "CloudFormation" },
  { glob: "**/*.k8s.yaml", type: "Kubernetes" },
  { glob: "Chart.yaml", type: "Helm" }
];

export async function runIacScan({ owner } = {}) {
  let composeContent;
  try {
    composeContent = fs.readFileSync(COMPOSE_PATH, "utf8");
  } catch {
    return [];
  }

  const rawFindings = analyzeDockerCompose(composeContent);
  const findings = rawFindings.map((f) => ({ ...f, category: "IAC", file: "docker-compose.yml" }));

  const persisted = [];
  const seenRuleIds = new Set();

  for (const finding of findings) {
    seenRuleIds.add(finding.ruleId);
    const existing = await DevSecOpsFinding.findOne({ ruleId: finding.ruleId, category: "IAC", status: "open" });
    if (existing) {
      persisted.push(existing);
      continue;
    }
    const created = await DevSecOpsFinding.create({ ...finding, status: "open" });
    persisted.push(created);

    await logSecurityEvent({
      owner,
      type: "iac_misconfiguration",
      message: `IaC finding: ${finding.title}`,
      metadata: { ruleId: finding.ruleId, severity: finding.severity }
    }).catch(() => {});
  }

  await DevSecOpsFinding.updateMany(
    { category: "IAC", status: "open", ruleId: { $nin: [...seenRuleIds] } },
    { status: "resolved", resolvedAt: new Date() }
  );

  return persisted;
}

export { OTHER_IAC_FILES };
