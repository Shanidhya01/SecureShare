/**
 * Phase 12 (DevSecOps/Supply Chain) tests, using Node's built-in test runner (same convention as
 * backend/tests/cloud.test.js). Every pure function is tested directly without a live MongoDB
 * connection or network access; DB-touching entry points are exercised only via their pure inner
 * helpers.
 * Run with: node --test backend/tests
 */
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "crypto";
import { detectProvider, extractRepoName } from "../services/devsecops/repositoryScanner.js";
import { levenshtein, detectTyposquat } from "../services/devsecops/dependencyScanner.js";
import { scanFileContent, shannonEntropy, SECRET_RULES } from "../services/devsecops/secretScanner.js";
import { scanFileForSast, SAST_RULES } from "../services/devsecops/sastScanner.js";
import { parseDockerfile } from "../services/devsecops/containerScanner.js";
import { analyzeDockerCompose } from "../services/devsecops/iacScanner.js";
import { extractComponents, buildCycloneDx, buildSpdx } from "../services/devsecops/sbomGenerator.js";
import { detectCiConfig } from "../services/devsecops/pipelineMonitor.js";
import { verifyArtifact } from "../services/devsecops/artifactSecurity.js";
import { computeFileHashes } from "../utils/fileHashes.js";
import { computeOverallScore } from "../services/devsecops/riskEngine.js";
import { eventTriggerFor, matchRules } from "../services/soar/ruleMatcher.js";
import { resolveEventMeta } from "../services/siem/eventCatalog.js";

/* ------------------------------- repositoryScanner ------------------------------- */

test("detectProvider identifies GitHub/GitLab/Azure DevOps/Bitbucket from a remote URL", () => {
  assert.equal(detectProvider("https://github.com/foo/bar.git"), "GitHub");
  assert.equal(detectProvider("git@gitlab.com:foo/bar.git"), "GitLab");
  assert.equal(detectProvider("https://dev.azure.com/org/project/_git/repo"), "AzureDevOps");
  assert.equal(detectProvider("https://bitbucket.org/foo/bar.git"), "Bitbucket");
  assert.equal(detectProvider("https://example.internal/foo/bar.git"), "Unknown");
  assert.equal(detectProvider(""), "Unknown");
});

test("extractRepoName pulls owner/repo from a remote URL", () => {
  assert.equal(extractRepoName("https://github.com/Shanidhya01/SecureShare.git"), "Shanidhya01/SecureShare");
  assert.equal(extractRepoName("git@github.com:Shanidhya01/SecureShare.git"), "Shanidhya01/SecureShare");
  assert.equal(extractRepoName(""), "local-repository");
});

/* ------------------------------- dependencyScanner ------------------------------- */

test("levenshtein computes edit distance", () => {
  assert.equal(levenshtein("express", "express"), 0);
  assert.equal(levenshtein("expres", "express"), 1);
  assert.equal(levenshtein("axios", "axois"), 2);
});

test("detectTyposquat flags a near-miss of a popular package but not an exact match", () => {
  assert.equal(detectTyposquat("express"), null);
  assert.equal(detectTyposquat("expres"), "express");
  assert.equal(detectTyposquat("totally-unrelated-package-name"), null);
});

/* ------------------------------- secretScanner ------------------------------- */

test("shannonEntropy is low for repetitive strings and high for random-looking ones", () => {
  assert.ok(shannonEntropy("aaaaaaaaaa") < 1);
  assert.ok(shannonEntropy("aG5xVzk3TkFsUCd7ZDsp") > 3.5);
});

test("scanFileContent detects an AWS access key with a masked preview", () => {
  const content = 'const key = "AKIAABCDEFGHIJKLMNOP";';
  const findings = scanFileContent("app.js", content);
  const awsFinding = findings.find((f) => f.ruleId === "secret:aws-access-key");
  assert.ok(awsFinding);
  assert.equal(awsFinding.severity, "CRITICAL");
  assert.doesNotMatch(awsFinding.metadata.preview, /AKIAABCDEFGHIJKLMNOP/);
});

test("scanFileContent detects a PEM private key block", () => {
  const content = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----";
  const findings = scanFileContent("id_rsa", content);
  assert.ok(findings.some((f) => f.ruleId === "secret:private-key"));
});

test("scanFileContent finds nothing in ordinary source code", () => {
  const content = "export function add(a, b) { return a + b; }";
  assert.deepEqual(scanFileContent("math.js", content), []);
});

test("scanFileContent respects checkEntropy: false for the generic entropy heuristic", () => {
  const content = '"aG5xVzk3TkFsUCd7ZDspXyZ9876543210AbCdEfGh"';
  const withEntropy = scanFileContent("config.yml", content, [], { checkEntropy: true });
  const withoutEntropy = scanFileContent("config.yml", content, [], { checkEntropy: false });
  assert.ok(withEntropy.some((f) => f.ruleId === "secret:high-entropy-string"));
  assert.ok(!withoutEntropy.some((f) => f.ruleId === "secret:high-entropy-string"));
});

test("SECRET_RULES covers every listed secret type at least once", () => {
  const ids = SECRET_RULES.map((r) => r.id);
  for (const expected of ["aws-access-key", "azure-key", "gcp-key", "github-token", "gitlab-token", "slack-token", "stripe-key", "openai-key", "private-key", "ssh-key", "jwt-token", "db-password"]) {
    assert.ok(ids.includes(expected), `missing rule for ${expected}`);
  }
});

/* ------------------------------- sastScanner ------------------------------- */

test("scanFileForSast detects eval() usage", () => {
  const findings = scanFileForSast("app.js", "function run(input) { return eval(input); }");
  assert.ok(findings.some((f) => f.ruleId === "sast:eval-usage"));
});

test("scanFileForSast detects a JWT signed without expiresIn but not one with it", () => {
  const insecure = scanFileForSast("auth.js", 'jwt.sign({ id }, secret);');
  assert.ok(insecure.some((f) => f.ruleId === "sast:insecure-jwt-no-expiry"));

  const secure = scanFileForSast("auth.js", 'jwt.sign({ id }, secret, { expiresIn: "1h" });');
  assert.ok(!secure.some((f) => f.ruleId === "sast:insecure-jwt-no-expiry"));
});

test("scanFileForSast detects an open redirect from user input", () => {
  const findings = scanFileForSast("routes.js", "res.redirect(req.query.next);");
  assert.ok(findings.some((f) => f.ruleId === "sast:open-redirect"));
});

test("scanFileForSast reports a line number matching the actual match location", () => {
  const content = "line1\nline2\nres.redirect(req.query.next);\nline4";
  const findings = scanFileForSast("routes.js", content);
  const finding = findings.find((f) => f.ruleId === "sast:open-redirect");
  assert.equal(finding.line, 3);
});

test("SAST_RULES entries all have an id, severity, and recommendation", () => {
  for (const rule of SAST_RULES) {
    assert.ok(rule.id);
    assert.ok(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(rule.severity));
    assert.ok(rule.recommendation);
  }
});

/* ------------------------------- containerScanner ------------------------------- */

test("parseDockerfile flags a missing USER directive as running-as-root", () => {
  const dockerfile = "FROM node:20-alpine\nWORKDIR /app\nCOPY . .\nCMD [\"node\", \"server.js\"]";
  const { findings } = parseDockerfile(dockerfile);
  assert.ok(findings.some((f) => f.ruleId === "container:running-as-root"));
});

test("parseDockerfile does not flag running-as-root when a USER directive is present", () => {
  const dockerfile = "FROM node:20-alpine\nUSER node\nCMD [\"node\", \"server.js\"]";
  const { findings } = parseDockerfile(dockerfile);
  assert.ok(!findings.some((f) => f.ruleId === "container:running-as-root"));
});

test("parseDockerfile flags a dev server CMD and a mutable :latest base image", () => {
  const dockerfile = "FROM node:latest\nUSER node\nCMD [\"npm\", \"run\", \"dev\"]";
  const { findings } = parseDockerfile(dockerfile);
  assert.ok(findings.some((f) => f.ruleId === "container:dev-server-in-production-image"));
  assert.ok(findings.some((f) => f.ruleId.includes("latest")));
});

test("parseDockerfile does not flag a pinned, non-dev-server Dockerfile beyond missing USER", () => {
  const dockerfile = "FROM node:20-alpine\nUSER node\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\nRUN npm ci\nCMD [\"node\", \"server.js\"]";
  const { findings } = parseDockerfile(dockerfile);
  assert.equal(findings.length, 0);
});

/* ------------------------------- iacScanner ------------------------------- */

test("analyzeDockerCompose flags a publicly-bound database port but not a loopback-bound one", () => {
  const compose = `services:\n  mongo:\n    image: mongo:7\n    ports:\n      - "27017:27017"\n`;
  const findings = analyzeDockerCompose(compose);
  assert.ok(findings.some((f) => f.ruleId === "iac:public-port:27017" && f.severity === "HIGH"));

  const safeCompose = `services:\n  mongo:\n    image: mongo:7\n    ports:\n      - "127.0.0.1:27017:27017"\n`;
  assert.ok(!analyzeDockerCompose(safeCompose).some((f) => f.ruleId === "iac:public-port:27017"));
});

test("analyzeDockerCompose flags privileged containers and host networking", () => {
  const compose = `services:\n  app:\n    image: app:1\n    privileged: true\n    network_mode: host\n`;
  const findings = analyzeDockerCompose(compose);
  assert.ok(findings.some((f) => f.ruleId === "iac:privileged-container"));
  assert.ok(findings.some((f) => f.ruleId === "iac:host-networking"));
});

test("analyzeDockerCompose scopes missing-restart-policy findings to each individual service", () => {
  const compose = `services:\n  backend:\n    image: app:1\n    restart: unless-stopped\n  mongo:\n    image: mongo:7\n`;
  const findings = analyzeDockerCompose(compose);
  assert.ok(!findings.some((f) => f.ruleId === "iac:missing-restart-policy:backend"));
  assert.ok(findings.some((f) => f.ruleId === "iac:missing-restart-policy:mongo"));
});

/* ------------------------------- sbomGenerator ------------------------------- */

const FAKE_LOCKFILE = {
  lockfileVersion: 3,
  packages: {
    "": { name: "root" },
    "node_modules/left-pad": { version: "1.3.0", resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", integrity: "sha512-YXQtZ4tsPKt/wHtdI5jsgyLm9J1joMPWOo9uwHqAlA0dgIe9hZo9YyxwiWkS90zC1JCsX/Y7c5j0USMYq5rrqA==", license: "MIT" }
  }
};

test("extractComponents builds a PURL/hash/license per real lockfile package", () => {
  const components = extractComponents(FAKE_LOCKFILE, "npm");
  assert.equal(components.length, 1);
  assert.equal(components[0].name, "left-pad");
  assert.equal(components[0].version, "1.3.0");
  assert.equal(components[0].purl, "pkg:npm/left-pad@1.3.0");
  assert.equal(components[0].license, "MIT");
  assert.ok(components[0].hash.algorithm.startsWith("SHA-"));
});

test("extractComponents skips the root project entry (empty key)", () => {
  const components = extractComponents(FAKE_LOCKFILE, "npm");
  assert.ok(!components.some((c) => c.name === "root"));
});

test("buildCycloneDx produces valid JSON with the expected component list", () => {
  const components = extractComponents(FAKE_LOCKFILE, "npm");
  const json = JSON.parse(buildCycloneDx(components, { serialization: "JSON" }));
  assert.equal(json.bomFormat, "CycloneDX");
  assert.equal(json.components.length, 1);
  assert.equal(json.components[0].purl, "pkg:npm/left-pad@1.3.0");
});

test("buildSpdx produces a document with an SPDX-2.3 version and one package", () => {
  const components = extractComponents(FAKE_LOCKFILE, "npm");
  const spdx = buildSpdx(components);
  assert.equal(spdx.spdxVersion, "SPDX-2.3");
  assert.equal(spdx.packages.length, 1);
  assert.equal(spdx.packages[0].name, "left-pad");
});

/* ------------------------------- pipelineMonitor ------------------------------- */

test("detectCiConfig reports booleans for every supported CI provider without throwing", () => {
  const config = detectCiConfig();
  assert.equal(typeof config.hasGithubActions, "boolean");
  assert.equal(typeof config.hasGitlabCi, "boolean");
  assert.equal(typeof config.hasJenkins, "boolean");
  assert.equal(typeof config.hasAzurePipelines, "boolean");
});

/* ------------------------------- artifactSecurity ------------------------------- */

// Small local helper mirroring artifactSecurity.js's internal hmacSign() so tests have a correct
// expected signature to compare against, without exporting an internal implementation detail from
// the module under test.
function expectedHmac(buffer) {
  const { sha256 } = computeFileHashes(buffer);
  const secret = process.env.JWT_SECRET || "insecure-default-secret";
  return crypto.createHmac("sha256", secret).update(sha256).digest("hex");
}

test("verifyArtifact confirms an unmodified artifact and detects tampering when the bytes change", () => {
  const original = Buffer.from("artifact-v1");
  const tampered = Buffer.from("artifact-v2-modified");
  const { sha256 } = computeFileHashes(original);
  const signatureRecord = { hash: sha256, hmacSignature: expectedHmac(original) };

  const originalResult = verifyArtifact(original, signatureRecord);
  const tamperedResult = verifyArtifact(tampered, signatureRecord);

  assert.equal(originalResult.valid, true);
  assert.equal(originalResult.hashMatches, true);
  assert.equal(tamperedResult.hashMatches, false);
  assert.equal(tamperedResult.valid, false);
});

/* ------------------------------- riskEngine ------------------------------- */

test("computeOverallScore returns 100 when every component score is 100", () => {
  const perfect = { repositoryScore: 100, dependencyScore: 100, secretScore: 100, containerScore: 100, pipelineScore: 100 };
  assert.equal(computeOverallScore(perfect), 100);
});

test("computeOverallScore clamps to [0, 100]", () => {
  const allZero = { repositoryScore: 0, dependencyScore: 0, secretScore: 0, containerScore: 0, pipelineScore: 0 };
  assert.equal(computeOverallScore(allZero), 0);
});

/* ------------------------------- SOAR integration (Phase 12 triggers) ------------------------------- */

test("eventTriggerFor maps new Phase 12 event types to their triggers", () => {
  assert.equal(eventTriggerFor({ type: "dependency_vulnerability", metadata: { severity: "CRITICAL" } }), "DEPENDENCY_VULNERABILITY_CRITICAL");
  assert.equal(eventTriggerFor({ type: "dependency_vulnerability", metadata: { severity: "LOW" } }), null);
  assert.equal(eventTriggerFor({ type: "secret_found", metadata: { severity: "HIGH" } }), "SECRET_FOUND_CRITICAL");
  assert.equal(eventTriggerFor({ type: "container_vulnerability", metadata: { severity: "CRITICAL" } }), "CONTAINER_VULNERABILITY_CRITICAL");
  assert.equal(eventTriggerFor({ type: "pipeline_blocked" }), "PIPELINE_BLOCKED");
  assert.equal(eventTriggerFor({ type: "high_risk_repository" }), "HIGH_RISK_REPOSITORY");
});

test("matchRules matches Phase 12 rules by their new trigger values", () => {
  const rules = [{ enabled: true, trigger: "HIGH_RISK_REPOSITORY", conditions: [], priority: 10, name: "repo" }];
  const matched = matchRules({ type: "high_risk_repository" }, rules);
  assert.equal(matched.length, 1);
  assert.equal(matched[0].name, "repo");
});

/* ------------------------------- SIEM integration (Phase 12 event catalog) ------------------------------- */

test("every Phase 12 SIEM event type resolves to the DEVSECOPS category", () => {
  const types = [
    "dependency_vulnerability", "secret_found", "sbom_generated", "sast_finding",
    "container_vulnerability", "pipeline_failed", "pipeline_blocked", "high_risk_repository",
    "iac_misconfiguration", "devsecops_scan", "devsecops_risk_updated"
  ];
  for (const type of types) {
    const meta = resolveEventMeta(type);
    assert.equal(meta.category, "DEVSECOPS", `${type} should resolve to DEVSECOPS category`);
    assert.ok(meta.siemType, `${type} should have a siemType`);
  }
});
