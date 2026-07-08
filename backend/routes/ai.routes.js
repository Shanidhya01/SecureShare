import express from "express";
import auth from "../middleware/auth.middleware.js";
import { aiLimiter } from "../middleware/rateLimit.js";
import {
  explainThreat,
  explainRisk,
  getMyInsights,
  askAssistant,
  generateSummary,
  exportSummaryPdf
} from "../controllers/ai.controller.js";

const router = express.Router();

// AI Security Assistant. Every route requires auth (users only ever get AI insight into their
// own data) plus the dedicated aiLimiter on top of the global apiLimiter already applied to all
// of /api/* in server.js.
router.post("/explain", auth, aiLimiter, explainThreat);
router.post("/explain-risk", auth, aiLimiter, explainRisk);
router.post("/ask", auth, aiLimiter, askAssistant);
router.post("/incident-summary", auth, aiLimiter, generateSummary);
// PDF export never calls Gemini (renders an already-generated AIInsight) but still stays under
// the same rate limit/auth policy as every other AI endpoint for consistency.
router.get("/incident-summary/:insightId/pdf", auth, aiLimiter, exportSummaryPdf);
router.get("/insights", auth, getMyInsights);

export default router;
