/**
 * Phase 13 (Platform Operations) - PART 8: Platform Reports (Health, Availability, Performance,
 * Queue, Infrastructure). Same buildCsv/buildJson/buildPdf trio convention as
 * services/compliance/reportGenerator.js and services/devsecops/devSecOpsReportGenerator.js.
 */
import PDFDocument from "pdfkit";
import { getLatestHealth, getHealthHistory } from "./healthChecker.js";
import { collectFullMetrics, getMetricsHistory } from "./metricsCollector.js";
import { listAlertHistory } from "./alertEngine.js";
import { getQueueStatus } from "./queue.js";

const REPORT_TYPES = ["health", "availability", "performance", "queue", "infrastructure"];

function computeAvailabilityPct(history) {
  if (!history.length) return 100;
  const healthy = history.filter((h) => h.overallStatus !== "CRITICAL").length;
  return Number(((healthy / history.length) * 100).toFixed(2));
}

export async function buildPlatformReportPayload(reportType = "health") {
  const type = REPORT_TYPES.includes(reportType) ? reportType : "health";
  const [health, healthHistory, metrics, metricsHistory, alerts, queue] = await Promise.all([
    getLatestHealth(),
    getHealthHistory({ hours: 24 * 7 }),
    collectFullMetrics(),
    getMetricsHistory({ hours: 24 * 7 }),
    listAlertHistory({ limit: 50 }),
    getQueueStatus()
  ]);

  return {
    reportType: type,
    generatedAt: new Date(),
    health,
    availabilityPct: computeAvailabilityPct(healthHistory),
    healthHistory,
    metrics,
    metricsHistory,
    alerts,
    queue
  };
}

function csvEscape(value) {
  return `"${String(value ?? "").replace(/"/g, '""')}"`;
}

export function buildCsv(payload) {
  const header = ["Report Type", "Generated At", "Overall Health Score", "Overall Status", "Availability %", "Avg API Latency (ms)", "Auth Success Rate %", "Queue Length", "Active Alerts"];
  const row = [
    payload.reportType,
    new Date(payload.generatedAt).toISOString(),
    payload.health.overallScore,
    payload.health.overallStatus,
    payload.availabilityPct,
    payload.metrics.api.avgLatencyMs,
    payload.metrics.auth.successRate,
    payload.metrics.queueLength,
    payload.alerts.filter((a) => a.active).length
  ];
  const componentHeader = ["Component", "Status", "Latency (ms)", "Message"];
  const componentRows = payload.health.components.map((c) => [c.name, c.status, c.latencyMs ?? "", c.message ?? ""]);
  return [header, row, [], componentHeader, ...componentRows].map((r) => r.map(csvEscape).join(",")).join("\n");
}

export function buildJson(payload) {
  return payload;
}

export function buildPdf(payload, res) {
  const doc = new PDFDocument({ margin: 50 });
  doc.pipe(res);

  doc.fontSize(20).text(`SecureShare Platform ${payload.reportType[0].toUpperCase()}${payload.reportType.slice(1)} Report`, { align: "center" });
  doc.moveDown();
  doc.fontSize(10).fillColor("#666").text(`Generated: ${new Date(payload.generatedAt).toISOString()}`, { align: "center" });
  doc.moveDown(2);

  doc.fillColor("#000").fontSize(14).text("Overview");
  doc.fontSize(11);
  doc.text(`Overall Health Score: ${payload.health.overallScore}/100 (${payload.health.overallStatus})`);
  doc.text(`Availability (7d): ${payload.availabilityPct}%`);
  doc.text(`Auth Success Rate: ${payload.metrics.auth.successRate}% (${payload.metrics.auth.successCount} success / ${payload.metrics.auth.failureCount} failed)`);
  doc.text(`Queue Length: ${payload.metrics.queueLength}`);
  doc.moveDown();

  doc.fontSize(14).text("Component Health");
  doc.fontSize(10);
  for (const c of payload.health.components) {
    doc
      .fillColor(c.status === "DOWN" ? "#B91C1C" : c.status === "DEGRADED" ? "#B45309" : "#065F46")
      .text(`[${c.status}] ${c.name}${c.latencyMs != null ? ` (${c.latencyMs}ms)` : ""}${c.message ? ` - ${c.message}` : ""}`);
  }
  doc.fillColor("#000").moveDown();

  doc.fontSize(14).text("API Performance");
  doc.fontSize(10);
  doc.text(`Requests (recent window): ${payload.metrics.api.requestCount}`);
  doc.text(`Avg Latency: ${payload.metrics.api.avgLatencyMs}ms, p95: ${payload.metrics.api.p95LatencyMs}ms, p99: ${payload.metrics.api.p99LatencyMs}ms`);
  doc.text(`Error Rate: ${payload.metrics.api.errorRate}%`);
  doc.moveDown();

  doc.fontSize(14).text("Recent Alerts");
  doc.fontSize(9);
  if (!payload.alerts.length) doc.text("No alerts recorded.");
  for (const a of payload.alerts.slice(0, 20)) {
    doc.text(`[${a.severity}] ${a.rule} - ${a.message} (${a.active ? "active" : "resolved"})`);
  }

  doc.end();
}
