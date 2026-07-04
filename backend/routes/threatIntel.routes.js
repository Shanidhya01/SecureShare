import express from "express";
import auth from "../middleware/auth.middleware.js";
import {
  scanText,
  getMyScans,
  getStats,
  searchIOC,
  listIOCs,
  getMitreCatalogHandler,
  getYaraRules,
  exportReport
} from "../controllers/threatIntel.controller.js";

const router = express.Router();

// On-demand IOC lookup over explicitly-submitted text/hashes (Phase 7) - never invoked against
// DLP's masked samples; a deliberate, auth-only exception like the Phase 4/5 scan endpoints.
router.post("/scan-text", auth, scanText);
router.get("/scans", auth, getMyScans);
router.get("/stats", auth, getStats);
router.get("/search", auth, searchIOC);
router.get("/iocs", auth, listIOCs);
router.get("/mitre", auth, getMitreCatalogHandler);
router.get("/yara-rules", auth, getYaraRules);
router.get("/export", auth, exportReport);

export default router;
