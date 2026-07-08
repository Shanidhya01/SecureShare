import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";

import authRoutes from "./routes/auth.routes.js";
import fileRoutes from "./routes/file.routes.js";
import userRoutes from "./routes/user.routes.js";
import deviceRoutes from "./routes/device.routes.js";
import sessionRoutes from "./routes/session.routes.js";
import securityRoutes from "./routes/security.routes.js";
import threatRoutes from "./routes/threat.routes.js";
import dlpRoutes from "./routes/dlp.routes.js";
import siemRoutes from "./routes/siem.routes.js";
import threatIntelRoutes from "./routes/threatIntel.routes.js";
import soarRoutes from "./routes/soar.routes.js";
import mfaRoutes from "./routes/mfa.routes.js";
import passkeyRoutes, { passkeyLoginRouter } from "./routes/passkey.routes.js";
import iamRoutes from "./routes/iam.routes.js";
import ipRoutes from "./routes/ip.routes.js";
import complianceRoutes from "./routes/compliance.routes.js";
import cloudRoutes from "./routes/cloud.routes.js";
import devsecopsRoutes from "./routes/devsecops.routes.js";
import platformRoutes from "./routes/platform.routes.js";
import aiRoutes from "./routes/ai.routes.js";
import { apiLimiter } from "./middleware/rateLimit.js";
import { requestContext } from "./middleware/requestContext.middleware.js";
import { metrics } from "./middleware/metrics.middleware.js";
import { getRedisClient } from "./middleware/redisClient.js";
import { ensureSeedRules } from "./services/threatIntel/yaraEngine.js";
import { ensureSeedPlaybooks } from "./services/soar/seedPlaybooks.js";
import { ensureSeedFrameworks } from "./services/compliance/seedFrameworks.js";
import { runAssessment } from "./services/compliance/complianceEngine.js";
import { runCloudScan } from "./services/cloud/cloudScanOrchestrator.js";
import { runDevSecOpsScan } from "./services/devsecops/devSecOpsOrchestrator.js";
import { runPlatformScan } from "./services/platform/platformOrchestrator.js";
import { initQueues } from "./services/platform/queue.js";
import { registerScheduledJob } from "./services/platform/scheduler.js";
import { recordScanDuration } from "./services/platform/metricsCollector.js";
import { logger } from "./utils/logger.js";
import User from "./models/User.js";

dotenv.config();

const app = express();
app.set("trust proxy", 1); // Trust the first proxy (load balancer, reverse proxy, etc.)
app.use(requestContext);
app.use(metrics);
app.use(cors());
app.use(express.json());
app.use("/api", apiLimiter);

// Fail fast instead of hanging: if MongoDB isn't connected yet (or the connection dropped), every
// query issued by a route handler would otherwise sit in Mongoose's command buffer until it times
// out (~10s, surfacing as a generic 500 with a "buffering timed out" message). /api/health is
// exempt so health checks/monitoring can still report the real DB status rather than being blocked
// by it.
//
// Serverless-specific fix: the one-time mongoose.connect() below (module load) only runs once per
// container. If that single attempt fails or is still racing when the first request arrives, a
// warm container would otherwise return 503 forever for its entire lifetime with no retry. This
// helper actively re-attempts the connection on demand instead, guarded so concurrent requests
// share one in-flight attempt rather than each starting their own.
let mongoReconnectPromise = null;

async function ensureMongoConnected() {
  if (mongoose.connection.readyState === 1) return true;
  if (!process.env.MONGO_URI) return false;

  if (mongoose.connection.readyState === 2) {
    // Already connecting (e.g. cold-start race) - wait briefly for it to settle instead of
    // firing a second, redundant connect() call.
    await new Promise((resolve) => {
      const cleanup = () => {
        mongoose.connection.off("connected", done);
        mongoose.connection.off("error", done);
      };
      const done = () => {
        cleanup();
        resolve();
      };
      mongoose.connection.once("connected", done);
      mongoose.connection.once("error", done);
      setTimeout(done, 4000);
    });
    return mongoose.connection.readyState === 1;
  }

  if (!mongoReconnectPromise) {
    mongoReconnectPromise = mongoose
      .connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 8000 })
      .then(() => console.log("MongoDB reconnected"))
      .catch((err) => console.error("MongoDB reconnect attempt failed:", err.message))
      .finally(() => {
        mongoReconnectPromise = null;
      });
  }
  await mongoReconnectPromise;
  return mongoose.connection.readyState === 1;
}

app.use("/api", async (req, res, next) => {
  if (req.path === "/health") return next();
  const connected = await ensureMongoConnected();
  if (!connected) {
    return res.status(503).json({ error: "Database unavailable. Please try again shortly." });
  }
  next();
});

// Phase 13 (Platform Operations): shared Redis client for rate limiting/queue/health checks.
// Non-fatal if REDIS_URL is unset or unreachable - every consumer degrades gracefully (Part 4/6).
getRedisClient();
initQueues();

if (!process.env.MONGO_URI) {
  console.error("MongoDB connection error: MONGO_URI is not set in backend/.env");
} else {
  mongoose
    .connect(process.env.MONGO_URI)
    .then(() => {
      console.log("MongoDB connected");
      ensureSeedRules().catch((err) => console.error("Failed to seed YARA rules:", err.message));
      ensureSeedPlaybooks().catch((err) => console.error("Failed to seed SOAR playbooks:", err.message));
      ensureSeedFrameworks().catch((err) => console.error("Failed to seed compliance frameworks:", err.message));
      registerAllScheduledJobs().catch((err) => console.error("Failed to register scheduled jobs:", err.message));
      runStartupCloudScan();
      runStartupDevSecOpsScan();
      runStartupPlatformScan();
    })
    .catch((err) => console.error("MongoDB connection error:", err.message));
}

mongoose.connection.on("error", (err) => {
  console.error("MongoDB connection error (post-connect):", err.message);
});

app.use("/api/auth", authRoutes);
app.use("/api/files", fileRoutes);
app.use("/api/users", userRoutes);
app.use("/api/devices", deviceRoutes);
app.use("/api/sessions", sessionRoutes);
app.use("/api/security", securityRoutes);
app.use("/api/threats", threatRoutes);
app.use("/api/dlp", dlpRoutes);
app.use("/api/siem", siemRoutes);
app.use("/api/threat-intel", threatIntelRoutes);
app.use("/api/soar", soarRoutes);
app.use("/api/mfa", mfaRoutes);
app.use("/api/passkeys", passkeyRoutes);
app.use("/api/auth/passkey", passkeyLoginRouter);
app.use("/api/iam", iamRoutes);
app.use("/api/compliance", complianceRoutes);
app.use("/api/cloud", cloudRoutes);
app.use("/api/devsecops", devsecopsRoutes);
app.use("/api/platform", platformRoutes);
app.use("/api/ai", aiRoutes);
app.use("/api", ipRoutes);

async function firstAdmin() {
  return User.findOne({ $or: [{ isAdmin: true }, { role: { $in: ["administrator", "org_owner"] } }] }).select("_id");
}

/** Times a scheduled scan and records it via metricsCollector.recordScanDuration (PART 2) -
 *  Phase 13's own instrumentation, no other phase's orchestrator code is touched. */
async function timedScan(metricKey, fn) {
  const start = Date.now();
  await fn();
  recordScanDuration(metricKey, Date.now() - start);
}

// Phase 13 (Platform Operations) PART 11: every recurring scan (Phase 10/11/12's daily scans, plus
// the new Phase 13 platform health/backup schedules) is registered through
// services/platform/scheduler.js instead of calling `cron.schedule` directly, so the Scheduler
// Dashboard can show last/next run, execution time, status, retries, and expose Run Now/Pause/
// Resume - the cron expressions/timing themselves are unchanged from before this phase.
async function registerAllScheduledJobs() {
  await registerScheduledJob({
    key: "compliance-daily-scan",
    label: "Daily Compliance Assessment",
    cronExpression: "0 3 * * *",
    fn: async () => {
      const admin = await firstAdmin();
      if (!admin) return;
      await timedScan("complianceScan", () => runAssessment({ owner: admin._id }));
    }
  });

  await registerScheduledJob({
    key: "cloud-daily-scan",
    label: "Daily Cloud Security Scan",
    cronExpression: "0 4 * * *",
    fn: async () => {
      const admin = await firstAdmin();
      if (!admin) return;
      await timedScan("cloudScan", () => runCloudScan({ owner: admin._id }));
    }
  });

  await registerScheduledJob({
    key: "devsecops-daily-scan",
    label: "Daily DevSecOps Scan",
    cronExpression: "0 5 * * *",
    fn: async () => {
      const admin = await firstAdmin();
      if (!admin) return;
      await timedScan("devSecOpsScan", () => runDevSecOpsScan({ owner: admin._id }));
    }
  });

  // Phase 13: platform health/metrics/alerts every 5 minutes, and a full database+audit backup
  // nightly at 02:00 (ahead of Compliance's 03:00 slot).
  await registerScheduledJob({
    key: "platform-health-scan",
    label: "Platform Health Check",
    cronExpression: "*/5 * * * *",
    fn: async () => {
      const admin = await firstAdmin();
      await runPlatformScan({ owner: admin?._id });
    }
  });

  await registerScheduledJob({
    key: "platform-nightly-backup",
    label: "Nightly Platform Backup",
    cronExpression: "0 2 * * *",
    fn: async () => {
      const { runBackup } = await import("./services/platform/backupManager.js");
      await runBackup({ type: "full" });
    }
  });
}

function runStartupCloudScan() {
  setTimeout(async () => {
    try {
      const admin = await firstAdmin();
      if (!admin) return;
      await runCloudScan({ owner: admin._id });
    } catch (err) {
      console.error("Startup cloud scan failed:", err.message);
    }
  }, 10000);
}

function runStartupDevSecOpsScan() {
  setTimeout(async () => {
    try {
      const admin = await firstAdmin();
      if (!admin) return;
      await runDevSecOpsScan({ owner: admin._id, checkLiveDependencies: false });
    } catch (err) {
      console.error("Startup DevSecOps scan failed:", err.message);
    }
  }, 15000);
}

function runStartupPlatformScan() {
  setTimeout(async () => {
    try {
      const admin = await firstAdmin();
      await runPlatformScan({ owner: admin?._id });
    } catch (err) {
      console.error("Startup platform scan failed:", err.message);
    }
  }, 20000);
}

// Root and health endpoints
app.get("/", (req, res) => {
  res.send("SecureShare API is running.");
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => logger.info("server_started", { port: PORT, env: process.env.NODE_ENV || "development", severity: "INFO" }));
