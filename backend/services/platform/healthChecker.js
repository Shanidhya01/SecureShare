/**
 * Phase 13 (Platform Operations) - PART 1: Cloud Health Engine. This project deploys to managed
 * cloud services only (frontend on Vercel, backend on Render, MongoDB Atlas, Redis Cloud,
 * Cloudinary, ClamAV in a Docker container on Render) - there is no host VM for this process to
 * introspect, so this deliberately does NOT check local CPU/disk/memory/network. Every check here
 * is a network reachability/latency probe against a managed dependency or a self-check against
 * this project's own two deployed services (backend/frontend), mirroring the "rule array +
 * weighted score" shape of services/cloud/scoreEngine.js and services/devsecops/riskEngine.js.
 * Every check degrades to a DOWN/UNKNOWN status rather than throwing, so a single unreachable
 * dependency never crashes the health check itself.
 */
import mongoose from "mongoose";
import net from "node:net";
import cloudinary from "../../utils/cloudinary.js";
import { getRedisClient, isRedisAvailable, getRedisStatus } from "../../middleware/redisClient.js";
import { getQueueStatus } from "./queue.js";
import PlatformHealthSnapshot from "../../models/PlatformHealthSnapshot.js";
import PlatformScheduledJob from "../../models/PlatformScheduledJob.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

// ClamAV runs as its own Docker service on Render (Part: "ClamAV API"), reachable over the same
// clamd INSTREAM/PING TCP protocol backend/services/clamavScanner.js already uses - CLAMAV_HOST
// points at that service's Render-internal hostname, not a local process.
const CLAMAV_HOST = process.env.CLAMAV_HOST || "127.0.0.1";
const CLAMAV_PORT = parseInt(process.env.CLAMAV_PORT) || 3310;
// The Vercel-deployed frontend's public URL, probed as an ordinary HTTP health check.
const FRONTEND_URL = process.env.FRONTEND_URL || process.env.WEBAUTHN_ORIGIN;

function timed(fn, timeoutMs = 3000) {
  return Promise.race([fn(), new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), timeoutMs))]);
}

async function checkMongo() {
  const start = Date.now();
  try {
    if (mongoose.connection.readyState !== 1) {
      return { name: "mongodb", status: "DOWN", message: `readyState=${mongoose.connection.readyState}` };
    }
    await timed(() => mongoose.connection.db.admin().ping());
    return { name: "mongodb", status: "UP", latencyMs: Date.now() - start };
  } catch (err) {
    return { name: "mongodb", status: "DOWN", message: err.message, latencyMs: Date.now() - start };
  }
}

async function checkRedis() {
  const status = getRedisStatus();
  if (!status.configured) return { name: "redis", status: "UNKNOWN", message: "REDIS_URL not configured" };
  const start = Date.now();
  try {
    const client = getRedisClient();
    if (!client || !isRedisAvailable()) return { name: "redis", status: "DOWN", message: status.lastError || "not connected" };
    await timed(() => client.ping());
    return { name: "redis", status: "UP", latencyMs: Date.now() - start };
  } catch (err) {
    return { name: "redis", status: "DOWN", message: err.message };
  }
}

async function checkClamAV() {
  const start = Date.now();
  try {
    const reply = await timed(
      () =>
        new Promise((resolve, reject) => {
          const socket = new net.Socket();
          let response = "";
          socket.setTimeout(2000);
          socket.once("timeout", () => { socket.destroy(); reject(new Error("timeout")); });
          socket.once("error", reject);
          socket.connect(CLAMAV_PORT, CLAMAV_HOST, () => socket.write("zPING\0"));
          socket.on("data", (d) => (response += d.toString("utf8")));
          socket.on("close", () => resolve(response));
        }),
      2500
    );
    const status = reply.includes("PONG") ? "UP" : "DEGRADED";
    return { name: "clamav", status, latencyMs: Date.now() - start };
  } catch (err) {
    return { name: "clamav", status: "DOWN", message: err.message };
  }
}

async function checkCloudinary() {
  if (!process.env.CLOUDINARY_CLOUD_NAME) return { name: "cloudinary", status: "UNKNOWN", message: "not configured" };
  const start = Date.now();
  try {
    await timed(() => cloudinary.api.ping(), 4000);
    return { name: "cloudinary", status: "UP", latencyMs: Date.now() - start };
  } catch (err) {
    return { name: "cloudinary", status: "DOWN", message: err.message };
  }
}

async function checkQueue() {
  try {
    const status = await getQueueStatus();
    const failedTotal = Object.values(status.queues || {}).reduce((sum, q) => sum + (q.failed || 0), 0);
    return { name: "queue", status: failedTotal > 20 ? "DEGRADED" : "UP", details: status };
  } catch (err) {
    return { name: "queue", status: "UNKNOWN", message: err.message };
  }
}

/** Self-check of this Render backend service - process is up and responsive, nothing host-level. */
function checkBackendApi() {
  return { name: "backend_api", status: "UP", details: { uptimeSec: Math.round(process.uptime()) } };
}

/** Probes the Vercel-deployed frontend's public URL for a reachable response. */
async function checkFrontend() {
  if (!FRONTEND_URL) return { name: "frontend_api", status: "UNKNOWN", message: "FRONTEND_URL not configured" };
  const start = Date.now();
  try {
    const res = await timed(() => fetch(FRONTEND_URL, { method: "GET" }), 5000);
    return { name: "frontend_api", status: res.ok ? "UP" : "DEGRADED", latencyMs: Date.now() - start, message: res.ok ? undefined : `HTTP ${res.status}` };
  } catch (err) {
    return { name: "frontend_api", status: "DOWN", message: err.message };
  }
}

/** Reports DEGRADED if any registered scheduled job's most recent run failed. */
async function checkScheduler() {
  try {
    const jobs = await PlatformScheduledJob.find().select("lastStatus label").lean();
    if (jobs.length === 0) return { name: "scheduler", status: "UNKNOWN", message: "no scheduled jobs registered yet" };
    const failed = jobs.filter((j) => j.lastStatus === "failed");
    return {
      name: "scheduler",
      status: failed.length === 0 ? "UP" : failed.length === jobs.length ? "DOWN" : "DEGRADED",
      details: { totalJobs: jobs.length, failing: failed.map((j) => j.label) }
    };
  } catch (err) {
    return { name: "scheduler", status: "UNKNOWN", message: err.message };
  }
}

const STATUS_SCORE = { UP: 100, DEGRADED: 60, DOWN: 0, UNKNOWN: 80 };
const WEIGHTS = {
  mongodb: 0.25,
  redis: 0.15,
  clamav: 0.15,
  cloudinary: 0.15,
  queue: 0.1,
  backend_api: 0.1,
  frontend_api: 0.05,
  scheduler: 0.05
};

function computeOverall(components) {
  let weightedSum = 0;
  let weightTotal = 0;
  for (const c of components) {
    const weight = WEIGHTS[c.name] ?? 0.05;
    weightedSum += (STATUS_SCORE[c.status] ?? 50) * weight;
    weightTotal += weight;
  }
  const score = Math.round(weightTotal ? weightedSum / weightTotal : 100);
  const overallStatus = score >= 90 ? "HEALTHY" : score >= 60 ? "WARNING" : "CRITICAL";
  return { score, overallStatus };
}

export async function runHealthCheck({ owner, persist = true } = {}) {
  const [mongo, redis, clamav, cloudinaryHealth, queue, frontend, scheduler] = await Promise.all([
    checkMongo(),
    checkRedis(),
    checkClamAV(),
    checkCloudinary(),
    checkQueue(),
    checkFrontend(),
    checkScheduler()
  ]);
  const backendApi = checkBackendApi();
  const components = [mongo, redis, clamav, cloudinaryHealth, queue, backendApi, frontend, scheduler];
  const { score, overallStatus } = computeOverall(components);

  let previous = null;
  if (persist) {
    previous = await PlatformHealthSnapshot.findOne().sort({ checkedAt: -1 }).lean();
  }

  const snapshot = persist
    ? await PlatformHealthSnapshot.create({ overallScore: score, overallStatus, components, checkedAt: new Date() })
    : { overallScore: score, overallStatus, components, checkedAt: new Date() };

  // SecurityEvent.owner is required - on a fresh database (no admin registered yet), the
  // startup/scheduled scan runs with owner undefined. The health snapshot is still recorded
  // either way; only the (owner-scoped) SIEM event is skipped until an owner exists.
  if (persist && previous && previous.overallStatus !== overallStatus && owner) {
    await logSecurityEvent({
      owner,
      type: "platform_health_changed",
      message: `Platform health changed from ${previous.overallStatus} to ${overallStatus} (score ${score})`,
      metadata: { previousStatus: previous.overallStatus, newStatus: overallStatus, score }
    }).catch(() => {});
  }

  return snapshot;
}

export async function getLatestHealth() {
  const latest = await PlatformHealthSnapshot.findOne().sort({ checkedAt: -1 }).lean();
  return latest || runHealthCheck({ persist: false });
}

export async function getHealthHistory({ hours = 24 } = {}) {
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);
  return PlatformHealthSnapshot.find({ checkedAt: { $gte: since } }).sort({ checkedAt: 1 }).lean();
}
