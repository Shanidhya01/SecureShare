import AIInsight from "../models/AIInsight.js";
import { logSecurityEvent } from "../services/siem/siemLogger.js";
import { explainThreat as runThreatExplanation, explainRisk as runRiskExplanation } from "../services/ai/aiExplanationService.js";
import { answerQuestion } from "../services/ai/chatService.js";
import { generateIncidentSummary, streamIncidentSummaryPdf } from "../services/ai/reportGenerator.js";

const VALID_SOURCE_TYPES = ["ThreatScan", "DLPScan", "File", "SecurityEvent"];
const ADMIN_ROLES = ["administrator", "org_owner"];

/** Shared ok/skipped/error response shaping for every AI endpoint that returns a single
 *  Gemini-generated result (explainThreat, explainRisk) - keeps the three-way status contract
 *  (and its HTTP status codes) identical everywhere instead of repeating it per handler. */
function respondWithResult(res, insight, result, payload) {
  if (result.status === "skipped") {
    return res.status(200).json({
      insightId: insight._id,
      status: "skipped",
      message: "AI Security Assistant is not configured (OPENROUTER_API_KEY is unset). Ask an administrator to enable it."
    });
  }
  if (result.status === "error") {
    return res.status(502).json({
      insightId: insight._id,
      status: "error",
      message: result.errorMessage || "AI request failed"
    });
  }
  return res.json({ insightId: insight._id, status: "ok", ...payload });
}

/**
 * AI Security Assistant - Feature 2 (AI Threat Explanation). "Explain with AI" button hits this
 * for any malware detection, DLP violation, suspicious event, invalid signature, or quarantined
 * file. Every call is recorded as an AIInsight (audit trail) and logged to SIEM, same fire-and-
 * forget pattern as every other controller in this codebase.
 */
export const explainThreat = async (req, res) => {
  try {
    const { sourceType, sourceId } = req.body || {};

    if (!sourceType || !VALID_SOURCE_TYPES.includes(sourceType)) {
      return res.status(400).json({ error: `sourceType must be one of: ${VALID_SOURCE_TYPES.join(", ")}` });
    }
    if (!sourceId || typeof sourceId !== "string") {
      return res.status(400).json({ error: "sourceId is required" });
    }

    const result = await runThreatExplanation(sourceType, sourceId, { id: req.user.id, role: req.user.role });

    const insight = await AIInsight.create({
      owner: req.user.id,
      type: "threat_explanation",
      sourceType,
      sourceId,
      prompt: result.prompt,
      response: result.explanation || result.rawText || null,
      model: process.env.OPENROUTER_MODEL || "openai/gpt-oss-120b:free",
      status: result.status,
      errorMessage: result.errorMessage || undefined
    });

    logSecurityEvent({
      owner: req.user.id,
      type: "ai_explanation_requested",
      message: `AI explanation requested for ${sourceType} ${sourceId}`,
      ip: req.headers["x-client-ip"] || req.ip,
      metadata: { sourceType, sourceId, status: result.status }
    }).catch((e) => console.error("Failed to record security event:", e));

    respondWithResult(res, insight, result, { explanation: result.explanation });
  } catch (err) {
    console.error("AI explainThreat error:", err);
    res.status(500).json({ error: err?.message || "AI explanation failed" });
  }
};

/**
 * AI Security Assistant - Feature 4 (AI Risk Explanation). "Explain" button next to any risk
 * score/level. Reuses the exact same context-gathering pipeline as explainThreat (Feature 2) via
 * services/ai/aiExplanationService.js's explainRisk - only the prompt template and expected
 * response shape differ.
 */
export const explainRisk = async (req, res) => {
  try {
    const { sourceType, sourceId } = req.body || {};

    if (!sourceType || !VALID_SOURCE_TYPES.includes(sourceType)) {
      return res.status(400).json({ error: `sourceType must be one of: ${VALID_SOURCE_TYPES.join(", ")}` });
    }
    if (!sourceId || typeof sourceId !== "string") {
      return res.status(400).json({ error: "sourceId is required" });
    }

    const result = await runRiskExplanation(sourceType, sourceId, { id: req.user.id, role: req.user.role });

    const insight = await AIInsight.create({
      owner: req.user.id,
      type: "risk_explanation",
      sourceType,
      sourceId,
      prompt: result.prompt,
      response: result.explanation || result.rawText || null,
      model: process.env.OPENROUTER_MODEL || "openai/gpt-oss-120b:free",
      status: result.status,
      errorMessage: result.errorMessage || undefined
    });

    logSecurityEvent({
      owner: req.user.id,
      type: "ai_risk_explanation_requested",
      message: `AI risk explanation requested for ${sourceType} ${sourceId}`,
      ip: req.headers["x-client-ip"] || req.ip,
      metadata: { sourceType, sourceId, status: result.status }
    }).catch((e) => console.error("Failed to record security event:", e));

    respondWithResult(res, insight, result, { explanation: result.explanation });
  } catch (err) {
    console.error("AI explainRisk error:", err);
    res.status(500).json({ error: err?.message || "AI risk explanation failed" });
  }
};

/* INSIGHT HISTORY - the requesting user's own past AI interactions, newest first. Backs the
   "Recent AI Insights" view (this feature's landing page now, Feature 5's dashboard later). */
export const getMyInsights = async (req, res) => {
  const insights = await AIInsight.find({ owner: req.user.id }).sort({ createdAt: -1 }).limit(100);
  res.json(insights);
};

/**
 * AI Security Assistant - Feature 1 (Q&A). Powers the dashboard's "Ask the AI Security Assistant"
 * widget (and, later, Feature 5's dedicated chat page) via services/ai/chatService.js. Same
 * response-shape convention as explainThreat above: ok/skipped/error, always recorded as an
 * AIInsight and logged to SIEM.
 */
export const askAssistant = async (req, res) => {
  try {
    const { question } = req.body || {};
    if (!question || typeof question !== "string" || !question.trim()) {
      return res.status(400).json({ error: "question is required" });
    }

    const result = await answerQuestion(question, { id: req.user.id });

    const insight = await AIInsight.create({
      owner: req.user.id,
      type: "chat_response",
      prompt: result.prompt,
      response: result.answer,
      model: process.env.OPENROUTER_MODEL || "openai/gpt-oss-120b:free",
      status: result.status,
      errorMessage: result.errorMessage || undefined
    });

    logSecurityEvent({
      owner: req.user.id,
      type: "ai_chat_query",
      message: "AI Security Assistant question asked",
      ip: req.headers["x-client-ip"] || req.ip,
      metadata: { status: result.status, sectionsUsed: result.sectionsUsed }
    }).catch((e) => console.error("Failed to record security event:", e));

    if (result.status === "skipped") {
      return res.status(200).json({
        insightId: insight._id,
        status: "skipped",
        message: "AI Security Assistant is not configured (OPENROUTER_API_KEY is unset). Ask an administrator to enable it."
      });
    }
    if (result.status === "error") {
      return res.status(result.errorMessage?.includes("required") || result.errorMessage?.includes("characters") ? 400 : 502).json({
        insightId: insight._id,
        status: "error",
        message: result.errorMessage || "AI Security Assistant failed to answer"
      });
    }

    res.json({
      insightId: insight._id,
      status: "ok",
      answer: result.answer
    });
  } catch (err) {
    console.error("AI askAssistant error:", err);
    res.status(500).json({ error: err?.message || "AI Security Assistant failed" });
  }
};

/**
 * AI Security Assistant - Feature 3 (AI Incident Summary). "Generate AI Incident Summary" button.
 * Gathers real stats via services/ai/contextBuilder.js (reused, not reimplemented), asks Gemini
 * only for the narrative layer (executive summary/overall health/recommendations) so the numbers
 * themselves are never something the model could hallucinate, and returns everything the frontend
 * needs to render, copy, or hand off to the markdown/PDF export endpoints.
 */
export const generateSummary = async (req, res) => {
  try {
    const isAdmin = !!req.user.isAdmin || ADMIN_ROLES.includes(req.user.role);
    const result = await generateIncidentSummary({ ownerId: req.user.id, isAdmin });

    const insight = await AIInsight.create({
      owner: req.user.id,
      type: "incident_summary",
      response: { stats: result.stats, narrative: result.narrative },
      model: process.env.OPENROUTER_MODEL || "openai/gpt-oss-120b:free",
      status: result.status,
      errorMessage: result.errorMessage || undefined
    });

    logSecurityEvent({
      owner: req.user.id,
      type: "ai_incident_summary_generated",
      message: "AI Incident Summary generated",
      ip: req.headers["x-client-ip"] || req.ip,
      metadata: { status: result.status }
    }).catch((e) => console.error("Failed to record security event:", e));

    if (result.status === "skipped") {
      return res.status(200).json({
        insightId: insight._id,
        status: "skipped",
        stats: result.stats,
        message: "AI narrative is not configured (OPENROUTER_API_KEY is unset), but the real stats below are still accurate."
      });
    }

    res.json({
      insightId: insight._id,
      status: result.status,
      stats: result.stats,
      narrative: result.narrative,
      markdown: result.markdown,
      message: result.status === "error" ? result.errorMessage : undefined
    });
  } catch (err) {
    console.error("AI generateSummary error:", err);
    res.status(500).json({ error: err?.message || "AI incident summary failed" });
  }
};

/**
 * AI Security Assistant - Feature 3 PDF export. Streams a PDF built (via pdfkit, same convention
 * as services/compliance/reportGenerator.js) from an already-generated AIInsight's stored stats/
 * narrative - never re-calls Gemini, so exporting is free and instant.
 */
export const exportSummaryPdf = async (req, res) => {
  const insight = await AIInsight.findOne({ _id: req.params.insightId, owner: req.user.id, type: "incident_summary" });
  if (!insight) return res.sendStatus(404);

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", "attachment; filename=secureshare-ai-incident-summary.pdf");
  streamIncidentSummaryPdf(res, { ...insight.response, generatedAt: insight.createdAt });
};
