/**
 * Phase 11 (CSPM/ASM): single entry point that runs a full CSPM/ASM scan - discovery, config scan,
 * certificate monitor, attack surface scan, threat-intel correlation, then the score engine -
 * mirrors services/compliance/complianceEngine.js's runAssessment() as the one function used by
 * the controller, the daily cron, and the startup scan.
 */
import { discoverAssets } from "./assetDiscovery.js";
import { runConfigScan } from "./configScanner.js";
import { runCertificateMonitor } from "./certificateMonitor.js";
import { runAttackSurfaceScan } from "./attackSurfaceScanner.js";
import { runThreatIntelCorrelation } from "./threatIntelCorrelation.js";
import { runScoreEngine } from "./scoreEngine.js";

export async function runCloudScan({ owner } = {}) {
  const assets = await discoverAssets({ owner });
  const configFindings = await runConfigScan({ owner });
  const certificates = await runCertificateMonitor({ owner });
  const exposureFindings = await runAttackSurfaceScan({ owner });
  const threatIntelFindings = await runThreatIntelCorrelation({ owner });
  const score = await runScoreEngine({ owner });

  return {
    assets: assets.length,
    configFindings: configFindings.length,
    certificates: certificates.length,
    exposureFindings: exposureFindings.filter((f) => !f.informational).length,
    threatIntelFindings: threatIntelFindings.length,
    score
  };
}
