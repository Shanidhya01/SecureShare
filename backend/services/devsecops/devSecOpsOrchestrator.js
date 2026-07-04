/**
 * Phase 12 (DevSecOps/Supply Chain): single entry point that runs a full DevSecOps scan -
 * repository, dependency, secret, SAST, container, IaC, pipeline, artifact security, then the
 * risk engine - mirrors services/cloud/cloudScanOrchestrator.js as the one function used by the
 * controller, the daily cron, and the startup scan.
 */
import { scanRepository } from "./repositoryScanner.js";
import { runDependencyScan } from "./dependencyScanner.js";
import { runSecretScan } from "./secretScanner.js";
import { runSastScan } from "./sastScanner.js";
import { runContainerScan } from "./containerScanner.js";
import { runIacScan } from "./iacScanner.js";
import { runPipelineMonitor } from "./pipelineMonitor.js";
import { runArtifactSecurityScan } from "./artifactSecurity.js";
import { runRiskEngine } from "./riskEngine.js";

export async function runDevSecOpsScan({ owner, checkLiveDependencies = true } = {}) {
  const repository = await scanRepository({ owner });
  const dependencyFindings = await runDependencyScan({ owner, checkLive: checkLiveDependencies });
  const secretFindings = await runSecretScan({ owner });
  const sastFindings = await runSastScan({ owner });
  const containerFindings = await runContainerScan({ owner });
  const iacFindings = await runIacScan({ owner });
  const pipeline = await runPipelineMonitor({ owner });
  const artifacts = await runArtifactSecurityScan();
  const score = await runRiskEngine({ owner });

  return {
    repository: repository.name,
    dependencyFindings: dependencyFindings.length,
    secretFindings: secretFindings.length,
    sastFindings: sastFindings.length,
    containerFindings: containerFindings.length,
    iacFindings: iacFindings.length,
    pipelineFindings: pipeline.findings.length,
    artifactsSigned: artifacts.length,
    score
  };
}
