import express from "express";
import multer from "multer";
import auth from "../middleware/auth.middleware.js";
import {
  scanFile,
  acknowledgeScan,
  getMyScans,
  getDLPStats,
  getDLPPolicy,
  getBlockedScans
} from "../controllers/dlp.controller.js";

const upload = multer();
const router = express.Router();

// The scan endpoint is one of the few places plaintext file bytes reach the server (Phase 5) -
// see controllers/dlp.controller.js for why this is a deliberate, scoped exception to the
// zero-knowledge model. Auth-only, never persists the uploaded buffer.
router.post("/scan", auth, upload.single("file"), scanFile);
router.post("/scans/:id/acknowledge", auth, acknowledgeScan);
router.get("/scans", auth, getMyScans);
router.get("/scans/blocked", auth, getBlockedScans);
router.get("/stats", auth, getDLPStats);
router.get("/policy", auth, getDLPPolicy);

export default router;
