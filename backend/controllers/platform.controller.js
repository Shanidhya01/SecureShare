import { runPlatformScan } from "../services/platform/platformOrchestrator.js";
import { getLatestHealth, getHealthHistory, runHealthCheck } from "../services/platform/healthChecker.js";
import { collectFullMetrics, getMetricsHistory } from "../services/platform/metricsCollector.js";
import { listActiveAlerts, listAlertHistory } from "../services/platform/alertEngine.js";
import { enqueueJob, getQueueStatus, QUEUE_NAMES } from "../services/platform/queue.js";
import PlatformJob from "../models/PlatformJob.js";
import { listScheduledJobs, runNow, pause, resume } from "../services/platform/scheduler.js";
import { runBackup, listBackups, validateBackup } from "../services/platform/backupManager.js";
import { buildPlatformReportPayload, buildCsv, buildJson, buildPdf } from "../services/platform/platformReportGenerator.js";
import { logSecurityEvent } from "../services/siem/siemLogger.js";

/* ============================== DASHBOARD ============================== */

export const getDashboard = async (_req, res) => {
  const [health, metrics, alerts, queue, scheduledJobs, recentJobs, backups] = await Promise.all([
    getLatestHealth(),
    collectFullMetrics(),
    listActiveAlerts(),
    getQueueStatus(),
    listScheduledJobs(),
    PlatformJob.find().sort({ createdAt: -1 }).limit(20).lean(),
    listBackups()
  ]);

  res.json({
    health,
    metrics,
    alerts,
    queue,
    scheduledJobs,
    recentJobs,
    recentBackups: backups.slice(0, 10)
  });
};

/* ============================== HEALTH ============================== */

export const getHealth = async (req, res) => {
  const fresh = req.query.fresh === "true";
  const health = fresh ? await runHealthCheck({ owner: req.user.id }) : await getLatestHealth();
  res.json(health);
};

export const getHealthHistoryEndpoint = async (req, res) => {
  const hours = Number(req.query.hours) || 24;
  const history = await getHealthHistory({ hours });
  res.json(history);
};

/* ============================== METRICS ============================== */

export const getMetrics = async (_req, res) => {
  const metrics = await collectFullMetrics();
  res.json(metrics);
};

export const getMetricsHistoryEndpoint = async (req, res) => {
  const hours = Number(req.query.hours) || 24;
  const history = await getMetricsHistory({ hours });
  res.json(history);
};

/* ============================== ALERTS ============================== */

export const getAlerts = async (req, res) => {
  const active = req.query.active !== "false";
  const alerts = active ? await listActiveAlerts() : await listAlertHistory({ limit: Number(req.query.limit) || 100 });
  res.json(alerts);
};

/* ============================== JOBS / QUEUE ============================== */

export const getJobs = async (req, res) => {
  const filter = {};
  if (req.query.queue) filter.queue = req.query.queue;
  if (req.query.status) filter.status = req.query.status;
  const [jobs, queueStatus] = await Promise.all([
    PlatformJob.find(filter).sort({ createdAt: -1 }).limit(200).lean(),
    getQueueStatus()
  ]);
  res.json({ jobs, queueStatus });
};

export const runJob = async (req, res) => {
  const { queue, payload } = req.body || {};
  if (!QUEUE_NAMES.includes(queue)) return res.status(400).json({ error: `queue must be one of: ${QUEUE_NAMES.join(", ")}` });
  const job = await enqueueJob({ queue, payload: { ...payload, owner: req.user.id }, owner: req.user.id });
  res.status(201).json(job);
};

/* ============================== SCHEDULER ============================== */

export const getScheduledJobs = async (_req, res) => {
  res.json(await listScheduledJobs());
};

export const runScheduledJobNow = async (req, res) => {
  await runNow(req.body.key);
  res.json({ success: true });
};

export const pauseScheduledJob = async (req, res) => {
  await pause(req.body.key);
  res.json({ success: true });
};

export const resumeScheduledJob = async (req, res) => {
  await resume(req.body.key);
  res.json({ success: true });
};

/* ============================== BACKUP ============================== */

export const createBackup = async (req, res) => {
  const type = req.body?.type || "full";
  const result = await runBackup({ type, triggeredBy: req.user.id });
  res.status(201).json(result);
};

export const getBackups = async (_req, res) => {
  res.json(await listBackups());
};

export const validateBackupEndpoint = async (req, res) => {
  const result = await validateBackup(req.body.backupId);
  res.json(result);
};

/* ============================== REPORTS ============================== */

export const listReports = async (_req, res) => {
  res.json({ types: ["health", "availability", "performance", "queue", "infrastructure"] });
};

export const generateReport = async (req, res) => {
  const reportType = req.body?.reportType || req.query.reportType || "health";
  const format = (req.body?.format || req.query.format || "json").toUpperCase();
  return sendReport(req, res, reportType, format);
};

/* ============================== EXPORT (PART 9: GET /api/platform/export/*) ============================== */

async function sendReport(req, res, reportType, format) {
  const payload = await buildPlatformReportPayload(reportType);
  const filename = `platform-${reportType}-report-${Date.now()}.${format.toLowerCase()}`;

  await logSecurityEvent({
    owner: req.user.id,
    type: "platform_report_generated",
    message: `Platform ${reportType} report generated (${format})`,
    metadata: { reportType, format }
  }).catch(() => {});

  if (format === "PDF") {
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    return buildPdf(payload, res);
  }
  if (format === "CSV") {
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    return res.send(buildCsv(payload));
  }
  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  return res.json(buildJson(payload));
}

export const exportPdf = (req, res) => sendReport(req, res, req.query.reportType || "health", "PDF");
export const exportCsv = (req, res) => sendReport(req, res, req.query.reportType || "health", "CSV");
export const exportJson = (req, res) => sendReport(req, res, req.query.reportType || "health", "JSON");

/* ============================== SCAN (manual trigger) ============================== */

export const runScan = async (req, res) => {
  const result = await runPlatformScan({ owner: req.user.id });
  res.json(result);
};
