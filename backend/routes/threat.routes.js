import express from "express";
import multer from "multer";
import auth from "../middleware/auth.middleware.js";
import {
  scanFile,
  getMyScans,
  getQuarantinedFiles,
  getThreatStats,
  releaseFromQuarantine
} from "../controllers/threat.controller.js";

const upload = multer();
const router = express.Router();

// The scan endpoint is the one place plaintext file bytes reach the server (Phase 4) - see
// controllers/threat.controller.js for why this is a deliberate, scoped exception to the
// zero-knowledge model. Auth-only, never persists the uploaded buffer.
router.post("/scan", auth, upload.single("file"), scanFile);
router.get("/scans", auth, getMyScans);
router.get("/quarantined", auth, getQuarantinedFiles);
router.get("/stats", auth, getThreatStats);
router.post("/quarantine/:id/release", auth, releaseFromQuarantine);

export default router;
