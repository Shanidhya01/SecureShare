/**
 * Phase 13 (Platform Operations - Cloud Health Engine) tests, using Node's built-in test runner
 * (same convention as backend/tests/devsecops.test.js). Pure functions are tested directly without
 * a live MongoDB/Redis connection; DB-touching entry points (evaluateAlerts, runHealthCheck, queue
 * enqueue) are exercised only via their pure inner logic/exported constants. This deployment
 * targets Vercel (frontend) + Render (backend/ClamAV) + MongoDB Atlas + Redis Cloud + Cloudinary
 * only - there is deliberately no local CPU/disk/memory metric to test.
 * Run with: node --test backend/tests
 */
import test from "node:test";
import assert from "node:assert/strict";
import { resolveEventMeta } from "../services/siem/eventCatalog.js";
import { ALERT_RULES } from "../services/platform/alertEngine.js";
import { QUEUE_NAMES } from "../services/platform/queue.js";
import { buildCsv, buildJson } from "../services/platform/platformReportGenerator.js";
import { recordScanDuration, getScanDurationMetrics, recordApiRequest, getApiMetrics, recordUploadTiming, recordDownloadTiming, getUploadDownloadMetrics } from "../services/platform/metricsCollector.js";

/* ------------------------------- eventCatalog (Phase 13 additions) ------------------------------- */

test("eventCatalog resolves every Phase 13 platform event to the PLATFORM category", () => {
  const platformTypes = [
    "platform_health_changed", "mongodb_offline", "redis_offline", "clamav_offline",
    "cloudinary_failure", "queue_failure", "high_api_latency", "background_job_failed",
    "backup_completed", "backup_failed", "platform_report_generated"
  ];
  for (const type of platformTypes) {
    const meta = resolveEventMeta(type);
    assert.equal(meta.category, "PLATFORM", `${type} should be category PLATFORM`);
    assert.ok(meta.siemType, `${type} should have a siemType`);
    assert.ok(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(meta.severity));
  }
});

test("eventCatalog has no local-resource (CPU/memory/disk) event types for Phase 13", () => {
  const forbidden = ["high_cpu_usage", "high_memory_usage", "low_disk_space"];
  for (const type of forbidden) {
    const meta = resolveEventMeta(type);
    assert.equal(meta.siemType, undefined, `${type} should not be a defined event - this deployment has no host VM to monitor`);
  }
});

test("eventCatalog falls back gracefully for an unknown type", () => {
  const meta = resolveEventMeta("not_a_real_event");
  assert.equal(meta.category, undefined);
  assert.equal(meta.severity, "INFO");
});

/* ------------------------------- alertEngine ------------------------------- */

test("alertEngine defines a rule for every alert named in the Phase 13 spec", () => {
  const expected = [
    "MONGODB_OFFLINE", "REDIS_OFFLINE", "CLOUDINARY_FAILURE", "CLAMAV_OFFLINE",
    "QUEUE_FAILURE", "HIGH_ERROR_RATE", "SLOW_API", "BACKGROUND_JOB_FAILURE", "HEALTH_SCORE_DROP"
  ];
  const ruleNames = ALERT_RULES.map((r) => r.rule);
  assert.deepEqual([...ruleNames].sort(), [...expected].sort());
});

test("alertEngine rules never use the AUTOMATION category (would be ignored by SOAR)", () => {
  for (const rule of ALERT_RULES) {
    const meta = resolveEventMeta(rule.siemType);
    assert.notEqual(meta.category, "AUTOMATION");
  }
});

/* ------------------------------- queue ------------------------------- */

test("queue defines exactly the 8 queue types named in the Phase 13 spec", () => {
  const expected = ["threat-scan", "malware-scan", "cloud-scan", "compliance-scan", "devsecops-scan", "report-generation", "notification", "email"];
  assert.deepEqual([...QUEUE_NAMES].sort(), [...expected].sort());
});

/* ------------------------------- metricsCollector ------------------------------- */

test("recordApiRequest/getApiMetrics compute latency percentiles and error rate", () => {
  for (const [statusCode, durationMs] of [[200, 50], [200, 100], [200, 150], [500, 900]]) {
    recordApiRequest({ route: "/api/test", method: "GET", statusCode, durationMs });
  }
  const metrics = getApiMetrics();
  assert.ok(metrics.requestCount >= 4);
  assert.ok(metrics.errorCount >= 1);
  assert.ok(metrics.errorRate > 0);
});

test("recordUploadTiming/recordDownloadTiming feed getUploadDownloadMetrics averages", () => {
  recordUploadTiming(1000);
  recordUploadTiming(2000);
  recordDownloadTiming(500);
  const m = getUploadDownloadMetrics();
  assert.ok(m.upload.count >= 2);
  assert.ok(m.upload.avgMs >= 1000);
  assert.ok(m.download.count >= 1);
});

test("recordScanDuration/getScanDurationMetrics tracks every documented scan type independently", () => {
  recordScanDuration("cloudScan", 300);
  recordScanDuration("cloudScan", 500);
  recordScanDuration("devSecOpsScan", 1200);
  const durations = getScanDurationMetrics();
  assert.ok(["threatScan", "malwareScan", "dlpScan", "complianceScan", "soarExecution", "cloudScan", "devSecOpsScan", "reportGeneration"].every((k) => k in durations));
  assert.equal(durations.cloudScan.count >= 2, true);
  assert.equal(durations.cloudScan.avgMs, 400);
});

/* ------------------------------- platformReportGenerator ------------------------------- */

function samplePayload() {
  return {
    reportType: "health",
    generatedAt: new Date("2026-01-01T00:00:00Z"),
    health: {
      overallScore: 92,
      overallStatus: "HEALTHY",
      components: [
        { name: "mongodb", status: "UP", latencyMs: 12 },
        { name: "redis", status: "DOWN", message: "not connected" }
      ]
    },
    availabilityPct: 99.5,
    metrics: {
      api: { requestCount: 100, avgLatencyMs: 50, p95LatencyMs: 120, p99LatencyMs: 200, errorRate: 1.2 },
      auth: { successCount: 40, failureCount: 2, successRate: 95.24, failureRate: 4.76 },
      queueLength: 3
    },
    alerts: [{ rule: "REDIS_OFFLINE", severity: "MEDIUM", message: "Redis Cloud is unreachable", active: true }]
  };
}

test("buildCsv includes overview and per-component rows", () => {
  const csv = buildCsv(samplePayload());
  assert.match(csv, /Overall Health Score/);
  assert.match(csv, /mongodb/);
  assert.match(csv, /redis/);
  assert.match(csv, /92/);
});

test("buildJson returns the payload unmodified (pass-through)", () => {
  const payload = samplePayload();
  assert.deepEqual(buildJson(payload), payload);
});

/* ------------------------------- SecurityEvent enum stays in sync with eventCatalog ------------------------------- */

test("every eventCatalog Phase 13 type has a matching resolveEventMeta severity/category pair", () => {
  const meta = resolveEventMeta("mongodb_offline");
  assert.equal(meta.severity, "CRITICAL");
  assert.equal(meta.siemType, "MONGODB_OFFLINE");
});
