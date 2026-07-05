/**
 * Phase 13 (Platform Operations): single entry point tying health + metrics + alerts together -
 * mirrors services/devsecops/devSecOpsOrchestrator.js as the one function used by the controller,
 * the scheduler, and the startup check.
 */
import { runHealthCheck } from "./healthChecker.js";
import { collectFullMetrics, snapshotMetrics } from "./metricsCollector.js";
import { evaluateAlerts } from "./alertEngine.js";

export async function runPlatformScan({ owner } = {}) {
  const health = await runHealthCheck({ owner });
  const metrics = await collectFullMetrics();
  await snapshotMetrics(metrics).catch(() => {});
  const alerts = await evaluateAlerts({ health, metrics, owner });

  return {
    overallScore: health.overallScore,
    overallStatus: health.overallStatus,
    componentCount: health.components.length,
    alertsTriggered: alerts.length,
    metrics
  };
}
