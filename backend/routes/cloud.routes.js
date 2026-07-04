import express from "express";
import auth from "../middleware/auth.middleware.js";
import requireAdmin from "../middleware/requireAdmin.js";
import {
  getDashboard,
  listAssets,
  getAsset,
  getFindings,
  acknowledgeFinding,
  resolveFinding,
  listCertificates,
  getScore,
  getHistory,
  runScan,
  exportReport
} from "../controllers/cloud.controller.js";

const router = express.Router();

// Phase 11 (CSPM/ASM): an org-wide deployment-posture concern, admin-only end to end - same
// gating pattern as Compliance/SOAR config (see compliance.routes.js).
router.use(auth, requireAdmin);

router.get("/dashboard", getDashboard);

router.get("/assets", listAssets);
router.get("/assets/:id", getAsset);

router.get("/findings", getFindings);
router.post("/findings/:id/acknowledge", acknowledgeFinding);
router.post("/findings/:id/resolve", resolveFinding);

router.get("/certificates", listCertificates);

router.get("/score", getScore);
router.get("/history", getHistory);

router.post("/scan", runScan);

router.get("/export/pdf", (req, res, next) => { req.params.format = "pdf"; next(); }, exportReport);
router.get("/export/csv", (req, res, next) => { req.params.format = "csv"; next(); }, exportReport);
router.get("/export/json", (req, res, next) => { req.params.format = "json"; next(); }, exportReport);

export default router;
