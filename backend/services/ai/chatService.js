/**
 * AI Security Assistant - Feature 1 (Q&A). Orchestrates a single question: build the relevant
 * real-data context, build the prompt, call Gemini, return a flat result for the controller to
 * persist/respond with. Same pure-orchestrator shape as aiExplanationService.js - never touches
 * req/res. Also the service Feature 5's dedicated AI Chat page will reuse unchanged.
 */
import User from "../../models/User.js";
import { buildSecurityContext } from "./contextBuilder.js";
import { buildSecurityAssistantPrompt } from "./promptTemplates.js";
import { generateContent } from "./geminiService.js";

const MAX_QUESTION_LENGTH = 2000;
const ADMIN_ROLES = ["administrator", "org_owner"];

/**
 * @param {string} question
 * @param {{ id: string }} user - only `id` is trusted from the caller; admin status is re-checked
 *   against the database here (never trusted from the JWT), same convention as
 *   middleware/requireAdmin.js, since it decides whether cross-user data enters the AI context.
 * @returns {Promise<{status: "ok"|"error"|"skipped", answer: string|null, prompt: string|null, sectionsUsed: string[], errorMessage: string|null}>}
 */
export async function answerQuestion(question, user) {
  const trimmed = (question || "").trim();
  if (!trimmed) {
    return { status: "error", answer: null, prompt: null, sectionsUsed: [], errorMessage: "Question is required" };
  }
  if (trimmed.length > MAX_QUESTION_LENGTH) {
    return { status: "error", answer: null, prompt: null, sectionsUsed: [], errorMessage: `Question must be under ${MAX_QUESTION_LENGTH} characters` };
  }

  const dbUser = await User.findById(user.id).select("isAdmin role");
  const isAdmin = !!dbUser?.isAdmin || ADMIN_ROLES.includes(dbUser?.role);
  const context = await buildSecurityContext(trimmed, { ownerId: user.id, isAdmin });
  const prompt = buildSecurityAssistantPrompt(trimmed, context);

  const result = await generateContent(prompt);

  if (result.status === "skipped") {
    return { status: "skipped", answer: null, prompt, sectionsUsed: context.sectionsIncluded, errorMessage: null };
  }
  if (result.status === "error") {
    return { status: "error", answer: null, prompt, sectionsUsed: context.sectionsIncluded, errorMessage: result.message };
  }

  return { status: "ok", answer: result.text.trim(), prompt, sectionsUsed: context.sectionsIncluded, errorMessage: null };
}
