/**
 * Phase 13 (Platform Operations) - PART 11: wraps every node-cron schedule (the pre-existing
 * Phase 10/11/12 daily scans plus the new Phase 13 ones) in a PlatformScheduledJob record so the
 * Scheduler Dashboard can show last/next run, execution time, status, retries, and let an admin
 * Run Now / Pause / Resume each one. server.js registers jobs via `registerScheduledJob` instead
 * of calling `cron.schedule` directly, keeping the exact same cron expressions/timing as before.
 */
import cron from "node-cron";
import PlatformScheduledJob from "../../models/PlatformScheduledJob.js";

const tasks = new Map(); // key -> { task, cronExpression, fn }

function nextRunEstimate(cronExpression) {
  // node-cron has no built-in "next run" API; approximate using the expression's hour/minute for
  // the common "M H * * *" daily-schedule shape used by every Phase 13 job, falling back to null.
  const parts = cronExpression.split(" ");
  if (parts.length === 5 && parts[2] === "*" && parts[3] === "*" && parts[4] === "*") {
    const [minute, hour] = parts;
    if (/^\d+$/.test(minute) && /^\d+$/.test(hour)) {
      const next = new Date();
      next.setHours(Number(hour), Number(minute), 0, 0);
      if (next <= new Date()) next.setDate(next.getDate() + 1);
      return next;
    }
  }
  return null;
}

async function ensureRecord(key, label, cronExpression) {
  let record = await PlatformScheduledJob.findOne({ key });
  if (!record) {
    record = await PlatformScheduledJob.create({ key, label, cronExpression, nextRunAt: nextRunEstimate(cronExpression) });
  }
  return record;
}

async function runAndTrack(key, fn) {
  const record = await PlatformScheduledJob.findOne({ key });
  const start = Date.now();
  try {
    await fn();
    if (record) {
      record.lastRunAt = new Date();
      record.lastDurationMs = Date.now() - start;
      record.lastStatus = "success";
      record.lastError = undefined;
      record.nextRunAt = nextRunEstimate(record.cronExpression);
      await record.save();
    }
  } catch (err) {
    if (record) {
      record.lastRunAt = new Date();
      record.lastDurationMs = Date.now() - start;
      record.lastStatus = "failed";
      record.lastError = err.message;
      record.failureCount += 1;
      record.nextRunAt = nextRunEstimate(record.cronExpression);
      await record.save();
    }
    throw err;
  }
}

/**
 * Registers a named cron job. `key` must be stable across restarts (used as the PlatformScheduledJob
 * primary key). Does not start disabled jobs (respects a prior `pause()` across restarts).
 */
export async function registerScheduledJob({ key, label, cronExpression, fn }) {
  const record = await ensureRecord(key, label, cronExpression);
  const task = cron.schedule(cronExpression, () => runAndTrack(key, fn).catch(() => {}), { scheduled: record.enabled });
  tasks.set(key, { task, cronExpression, fn });
}

export async function runNow(key) {
  const entry = tasks.get(key);
  if (!entry) throw new Error(`No scheduled job registered for key "${key}"`);
  await runAndTrack(key, entry.fn);
}

export async function pause(key) {
  const entry = tasks.get(key);
  if (!entry) throw new Error(`No scheduled job registered for key "${key}"`);
  entry.task.stop();
  await PlatformScheduledJob.updateOne({ key }, { enabled: false });
}

export async function resume(key) {
  const entry = tasks.get(key);
  if (!entry) throw new Error(`No scheduled job registered for key "${key}"`);
  entry.task.start();
  await PlatformScheduledJob.updateOne({ key }, { enabled: true });
}

export async function listScheduledJobs() {
  return PlatformScheduledJob.find().sort({ key: 1 }).lean();
}
