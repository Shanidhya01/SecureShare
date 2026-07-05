/**
 * Phase 13 (Platform Operations) - PART 5: Background Job Queue. BullMQ-backed when Redis is
 * configured and reachable; otherwise falls back to running jobs immediately in-process (still
 * recorded in PlatformJob with status/duration/retryCount/logs) so the platform keeps working
 * without Redis, per spec Part 4/6 ("gracefully fall back if Redis is unavailable").
 *
 * Each queue's handler forwards to the existing orchestrator for that scan type - no scan logic is
 * duplicated here, this only adds queueing/persistence/retry around calls that already exist
 * (runDevSecOpsScan, runCloudScan, runAssessment, etc).
 */
import { Queue, Worker } from "bullmq";
import { getRedisClient, isRedisAvailable } from "../../middleware/redisClient.js";
import PlatformJob from "../../models/PlatformJob.js";
import { logSecurityEvent } from "../siem/siemLogger.js";
import { logger } from "../../utils/logger.js";
import { recordScanDuration } from "./metricsCollector.js";

export const QUEUE_NAMES = [
  "threat-scan",
  "malware-scan",
  "cloud-scan",
  "compliance-scan",
  "devsecops-scan",
  "report-generation",
  "notification",
  "email"
];

// Maps a queue name to the scan-duration metric key it feeds (PART 2) - notification/email aren't
// "scans" so they're intentionally left unmapped.
const SCAN_METRIC_KEY = {
  "threat-scan": "threatScan",
  "malware-scan": "malwareScan",
  "cloud-scan": "cloudScan",
  "compliance-scan": "complianceScan",
  "devsecops-scan": "devSecOpsScan",
  "report-generation": "reportGeneration"
};

const queues = new Map();
const workers = new Map();
let handlers = {};

/** Lazily registers handlers to avoid circular imports at module-load time. */
function getHandlers() {
  if (Object.keys(handlers).length) return handlers;
  handlers = {
    "threat-scan": async () => ({ note: "threat scans run inline on upload; queue provided for on-demand re-scans" }),
    "malware-scan": async () => ({ note: "malware scans run inline on upload; queue provided for on-demand re-scans" }),
    "cloud-scan": async (payload) => {
      const { runCloudScan } = await import("../cloud/cloudScanOrchestrator.js");
      return runCloudScan({ owner: payload.owner });
    },
    "compliance-scan": async (payload) => {
      const { runAssessment } = await import("../compliance/complianceEngine.js");
      return runAssessment({ owner: payload.owner });
    },
    "devsecops-scan": async (payload) => {
      const { runDevSecOpsScan } = await import("../devsecops/devSecOpsOrchestrator.js");
      return runDevSecOpsScan({ owner: payload.owner, checkLiveDependencies: payload.checkLiveDependencies !== false });
    },
    "report-generation": async (payload) => {
      const { buildPlatformReportPayload } = await import("./platformReportGenerator.js");
      return buildPlatformReportPayload(payload.reportType);
    },
    notification: async (payload) => {
      const { default: notifyUser } = await import("../soar/actions/notifyUser.js");
      return notifyUser(payload, payload.event || {});
    },
    email: async (payload) => {
      const { default: sendEmail } = await import("../soar/actions/sendEmail.js");
      return sendEmail(payload, payload.event || {});
    }
  };
  return handlers;
}

function useBullMQ() {
  return !!process.env.REDIS_URL && isRedisAvailable();
}

export function initQueues() {
  if (!process.env.REDIS_URL) {
    logger.info("platform_queue_fallback_mode", { severity: "INFO", reason: "REDIS_URL not set" });
    return;
  }
  const connection = getRedisClient();
  for (const name of QUEUE_NAMES) {
    const queue = new Queue(name, { connection });
    queues.set(name, queue);

    const worker = new Worker(
      name,
      async (job) => {
        const record = await PlatformJob.findById(job.data.jobRecordId);
        return runJobHandler(name, job.data.payload, record);
      },
      { connection }
    );
    worker.on("failed", (job, err) => {
      logger.error("platform_job_failed", { queue: name, jobId: job?.id, error: err.message, severity: "ERROR" });
    });
    workers.set(name, worker);
  }
}

async function runJobHandler(queueName, payload, record) {
  const start = Date.now();
  try {
    if (record) {
      record.status = "running";
      record.startedAt = new Date();
      record.logs.push({ message: "job started" });
      await record.save();
    }
    const result = await getHandlers()[queueName](payload || {});
    const durationMs = Date.now() - start;
    if (SCAN_METRIC_KEY[queueName]) recordScanDuration(SCAN_METRIC_KEY[queueName], durationMs);
    if (record) {
      record.status = "completed";
      record.result = result;
      record.durationMs = durationMs;
      record.finishedAt = new Date();
      record.logs.push({ message: "job completed" });
      await record.save();
    }
    return result;
  } catch (err) {
    if (record) {
      record.status = "failed";
      record.error = err.message;
      record.durationMs = Date.now() - start;
      record.finishedAt = new Date();
      record.retryCount += 1;
      record.logs.push({ message: `job failed: ${err.message}` });
      await record.save();
    }
    await logSecurityEvent({
      owner: record?.owner,
      type: "background_job_failed",
      message: `Background job failed: ${queueName} (${err.message})`,
      metadata: { queue: queueName, error: err.message }
    }).catch(() => {});
    throw err;
  }
}

/**
 * Enqueues a job. Returns the created PlatformJob record. If Redis/BullMQ is unavailable, the
 * handler runs immediately in-process (still tracked identically in PlatformJob).
 */
export async function enqueueJob({ queue, payload = {}, owner, maxRetries = 3 } = {}) {
  if (!QUEUE_NAMES.includes(queue)) throw new Error(`Unknown queue: ${queue}`);

  const record = await PlatformJob.create({ queue, owner, payload, status: "queued", maxRetries, logs: [{ message: "job queued" }] });

  if (useBullMQ() && queues.has(queue)) {
    const bullQueue = queues.get(queue);
    await bullQueue.add(queue, { payload, jobRecordId: record._id.toString() }, { attempts: maxRetries, backoff: { type: "exponential", delay: 2000 } });
    record.jobId = `${queue}:${record._id}`;
    await record.save();
    return record;
  }

  // Fallback: run inline, fire-and-forget from the caller's perspective but awaited here so
  // callers of POST /api/platform/jobs/run get a synchronous result when Redis is down.
  await runJobHandler(queue, payload, record).catch(() => {});
  return PlatformJob.findById(record._id);
}

export async function getQueueLength() {
  if (!useBullMQ()) {
    const count = await PlatformJob.countDocuments({ status: { $in: ["queued", "running"] } });
    return count;
  }
  let total = 0;
  for (const q of queues.values()) {
    total += await q.getWaitingCount();
  }
  return total;
}

export async function getQueueStatus() {
  if (!useBullMQ()) {
    const [queued, running, completed, failed] = await Promise.all([
      PlatformJob.countDocuments({ status: "queued" }),
      PlatformJob.countDocuments({ status: "running" }),
      PlatformJob.countDocuments({ status: "completed" }),
      PlatformJob.countDocuments({ status: "failed" })
    ]);
    return { mode: "fallback", queues: { inProcess: { waiting: queued, active: running, completed, failed } } };
  }
  const status = {};
  for (const [name, q] of queues.entries()) {
    status[name] = await q.getJobCounts();
  }
  return { mode: "bullmq", queues: status };
}

export async function closeQueues() {
  for (const w of workers.values()) await w.close();
  for (const q of queues.values()) await q.close();
}
