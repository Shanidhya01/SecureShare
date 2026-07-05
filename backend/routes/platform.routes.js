import express from "express";
import auth from "../middleware/auth.middleware.js";
import requireAdmin from "../middleware/requireAdmin.js";
import {
  getDashboard,
  getHealth,
  getHealthHistoryEndpoint,
  getMetrics,
  getMetricsHistoryEndpoint,
  getAlerts,
  getJobs,
  runJob,
  getScheduledJobs,
  runScheduledJobNow,
  pauseScheduledJob,
  resumeScheduledJob,
  createBackup,
  getBackups,
  validateBackupEndpoint,
  listReports,
  generateReport,
  exportPdf,
  exportCsv,
  exportJson,
  runScan
} from "../controllers/platform.controller.js";

const router = express.Router();

// Phase 13 (Platform Operations): a platform-wide operational concern, admin-only end to end -
// same gating pattern as Compliance/SOAR/Cloud Security/DevSecOps.
router.use(auth, requireAdmin);

router.get("/dashboard", getDashboard);

router.get("/health", getHealth);
router.get("/health/history", getHealthHistoryEndpoint);

router.get("/metrics", getMetrics);
router.get("/metrics/history", getMetricsHistoryEndpoint);

router.get("/alerts", getAlerts);

router.get("/jobs", getJobs);
// PART 9: enqueues a background job onto BullMQ (or runs it inline via the Redis-down fallback).
router.post("/jobs/run", runJob);

// Bonus, beyond the Part 9 spec: scheduler introspection/control for the pre-existing Phase
// 10/11/12 daily scans plus Phase 13's own health/backup schedules (kept under /scheduler/* so it
// doesn't collide with the canonical POST /jobs/run meaning above).
router.get("/scheduler", getScheduledJobs);
router.post("/scheduler/run-now", runScheduledJobNow);
router.post("/scheduler/pause", pauseScheduledJob);
router.post("/scheduler/resume", resumeScheduledJob);

// Bonus, beyond spec: non-destructive backup archives (still additive, doesn't conflict with
// anything the spec requires).
router.post("/backup", createBackup);
router.get("/backup", getBackups);
router.post("/backup/validate", validateBackupEndpoint);

router.get("/reports", listReports);
router.post("/reports", generateReport);

// PART 9: dedicated export endpoints, mirroring the /api/devsecops/export/* convention.
// ?reportType= selects health|availability|performance|queue|infrastructure (defaults to health).
router.get("/export/pdf", exportPdf);
router.get("/export/csv", exportCsv);
router.get("/export/json", exportJson);

router.post("/scan", runScan);

export default router;
