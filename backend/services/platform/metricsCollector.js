/**
 * Phase 13 (Platform Operations) - PART 2: Platform Metrics. In-memory ring buffers of recent API/
 * upload/download/scan timings, plus authentication success/failure rates and scan-activity counts
 * pulled from existing models (no duplication - Threat/DLP/SOAR/Compliance/Cloud/DevSecOps/IAM
 * already persist their own activity; this only aggregates/times it, mirroring
 * services/compliance/evidenceCollector.js's read-only aggregation pattern). This deployment has no
 * host VM to introspect, so there is deliberately no CPU/memory/disk metric here - only
 * application- and managed-dependency-level measurements. A periodic snapshot is persisted to
 * PlatformMetricSnapshot (mirrors Phase 11's SecurityScoreSnapshot) so history survives restarts
 * without adding a time-series DB.
 */
import ThreatScan from "../../models/ThreatScan.js";
import DLPScan from "../../models/DLPScan.js";
import AutomationExecution from "../../models/AutomationExecution.js";
import ComplianceAssessment from "../../models/ComplianceAssessment.js";
import DevSecOpsFinding from "../../models/DevSecOpsFinding.js";
import CloudFinding from "../../models/CloudFinding.js";
import SecurityEvent from "../../models/SecurityEvent.js";
import PlatformMetricSnapshot from "../../models/PlatformMetricSnapshot.js";
import { getQueueLength } from "./queue.js";

const RING_SIZE = 2000;
const requestRing = [];
let uploadTimings = [];
let downloadTimings = [];

// Duration ring buffers per scan/job type, recorded by services/platform/queue.js (background jobs)
// and server.js's scheduler registrations (scheduled scans) - the only places Phase 13 code itself
// invokes another phase's orchestrator, so no other phase's files need to be touched to time them.
const SCAN_TYPES = ["threatScan", "malwareScan", "dlpScan", "complianceScan", "soarExecution", "cloudScan", "devSecOpsScan", "reportGeneration"];
const scanTimings = Object.fromEntries(SCAN_TYPES.map((t) => [t, []]));

export function recordApiRequest({ route, method, statusCode, durationMs }) {
  requestRing.push({ route, method, statusCode, durationMs, at: Date.now() });
  if (requestRing.length > RING_SIZE) requestRing.shift();
}

export function recordUploadTiming(durationMs) {
  uploadTimings.push(durationMs);
  if (uploadTimings.length > 500) uploadTimings = uploadTimings.slice(-500);
}

export function recordDownloadTiming(durationMs) {
  downloadTimings.push(durationMs);
  if (downloadTimings.length > 500) downloadTimings = downloadTimings.slice(-500);
}

/** @param {"threatScan"|"malwareScan"|"dlpScan"|"complianceScan"|"soarExecution"|"cloudScan"|"devSecOpsScan"|"reportGeneration"} type */
export function recordScanDuration(type, durationMs) {
  if (!scanTimings[type]) return;
  scanTimings[type].push(durationMs);
  if (scanTimings[type].length > 200) scanTimings[type] = scanTimings[type].slice(-200);
}

function percentile(values, p) {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return Math.round(sorted[idx]);
}

function average(values) {
  return values.length ? Math.round(values.reduce((a, b) => a + b, 0) / values.length) : 0;
}

export function getApiMetrics() {
  const durations = requestRing.map((r) => r.durationMs);
  const errors = requestRing.filter((r) => r.statusCode >= 500).length;
  return {
    requestCount: requestRing.length,
    avgLatencyMs: average(durations),
    p95LatencyMs: percentile(durations, 95),
    p99LatencyMs: percentile(durations, 99),
    errorCount: errors,
    errorRate: requestRing.length ? Number(((errors / requestRing.length) * 100).toFixed(2)) : 0
  };
}

export function getUploadDownloadMetrics() {
  return {
    upload: { count: uploadTimings.length, avgMs: average(uploadTimings), p95Ms: percentile(uploadTimings, 95) },
    download: { count: downloadTimings.length, avgMs: average(downloadTimings), p95Ms: percentile(downloadTimings, 95) }
  };
}

export function getScanDurationMetrics() {
  return Object.fromEntries(SCAN_TYPES.map((t) => [t, { count: scanTimings[t].length, avgMs: average(scanTimings[t]), p95Ms: percentile(scanTimings[t], 95) }]));
}

/** Authentication success/failure rate, reusing Phase 9's existing `login`/`login_failed` SIEM
 *  events (backend/services/iam/loginFailureTracker.js) rather than instrumenting the auth
 *  controller directly - no Phase 9 code is touched. */
export async function getAuthMetrics({ hours = 24 } = {}) {
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);
  const [success, failed] = await Promise.all([
    SecurityEvent.countDocuments({ type: "login", createdAt: { $gte: since } }),
    SecurityEvent.countDocuments({ type: "login_failed", createdAt: { $gte: since } })
  ]);
  const total = success + failed;
  return {
    successCount: success,
    failureCount: failed,
    successRate: total ? Number(((success / total) * 100).toFixed(2)) : 100,
    failureRate: total ? Number(((failed / total) * 100).toFixed(2)) : 0
  };
}

export async function getScanActivityMetrics() {
  const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const [threatScans, dlpScans, soarExecutions, complianceScans, cloudScans, devSecOpsScans] = await Promise.all([
    ThreatScan.countDocuments({ createdAt: { $gte: since24h } }).catch(() => 0),
    DLPScan.countDocuments({ createdAt: { $gte: since24h } }).catch(() => 0),
    AutomationExecution.countDocuments({ createdAt: { $gte: since24h } }).catch(() => 0),
    ComplianceAssessment.countDocuments({ createdAt: { $gte: since24h } }).catch(() => 0),
    CloudFinding.countDocuments({ detectedAt: { $gte: since24h } }).catch(() => 0),
    DevSecOpsFinding.countDocuments({ detectedAt: { $gte: since24h } }).catch(() => 0)
  ]);
  return { threatScans, dlpScans, soarExecutions, complianceScans, cloudScans, devSecOpsScans };
}

export async function collectFullMetrics() {
  const [scanActivity, queueLength, auth] = await Promise.all([getScanActivityMetrics(), getQueueLength(), getAuthMetrics()]);
  return {
    api: getApiMetrics(),
    uploadDownload: getUploadDownloadMetrics(),
    scanDurations: getScanDurationMetrics(),
    auth,
    scanActivity,
    queueLength
  };
}

export async function snapshotMetrics(precomputedMetrics) {
  const metrics = precomputedMetrics || (await collectFullMetrics());
  return PlatformMetricSnapshot.create({ ...metrics, recordedAt: new Date() });
}

export async function getMetricsHistory({ hours = 24 } = {}) {
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);
  return PlatformMetricSnapshot.find({ recordedAt: { $gte: since } }).sort({ recordedAt: 1 }).lean();
}
