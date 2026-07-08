/**
 * AI Security Assistant: every reusable prompt-building block lives here, in services/ai/, not
 * inside any controller (Feature 7/8's "prompt engineering" requirement). Consolidates what was
 * previously a separate top-level backend/prompts/ folder into one module alongside the rest of
 * the AI service layer - one place to find every template.
 */

export const SYSTEM_PREAMBLE =
  "You are a security analyst assistant embedded inside SecureShare, a zero-knowledge encrypted " +
  "file-sharing platform with built-in malware scanning, DLP, SIEM/SOAR automation, and threat " +
  "intelligence. You are explaining real detections and real project data to the user who owns " +
  "this account.";

/**
 * Every prompt that asks Gemini to reason about metadata must include this clause verbatim.
 * This is the concrete mechanism behind "do not hallucinate": it instructs the model to say so
 * explicitly whenever a field is missing, restricted, or empty, rather than inventing detail to
 * fill the gap.
 */
export const NO_HALLUCINATION_CLAUSE =
  "Only use the facts provided in the CONTEXT block below. Do not invent file contents, scanner " +
  "output, user identities, or any detail not present in CONTEXT. If a field is missing, null, " +
  'empty, or marked "restricted", do not guess - say so plainly instead of fabricating an answer.';

/** Wraps an arbitrary JSON-serializable context object into a labeled CONTEXT block. */
export function formatContextBlock(context) {
  return `CONTEXT (JSON):\n${JSON.stringify(context, null, 2)}`;
}

/** Instructs Gemini to respond with raw JSON only - no markdown fences, no prose around it. */
export const JSON_ONLY_CLAUSE =
  "Respond with ONLY a single valid JSON object matching the schema below. Do not wrap it in " +
  "markdown code fences, do not add any explanation before or after the JSON.";

const THREAT_EXPLANATION_SCHEMA = `{
  "executiveSummary": string,   // 2-3 sentence, non-technical summary for a business stakeholder
  "whatHappened": string,       // plain-language summary of the detection event
  "whyDetected": string,        // which signal(s)/rule(s)/scanner/IOC/MITRE technique triggered this, and why
  "businessImpact": string,     // what this means for the organization/account owner in business terms
  "technicalImpact": string,    // the concrete technical consequence (data exposure, lateral movement risk, etc)
  "riskLevel": string,          // one of: "Low", "Medium", "High", "Critical" - your own assessment given the context
  "recommendedActions": string[], // concrete, ordered next steps for this specific user/file
  "preventionTips": string[],   // general tips to avoid this class of issue in the future
  "assumptions": string[]       // required by NO_HALLUCINATION_CLAUSE - empty array if nothing was missing
}`;

const RISK_EXPLANATION_SCHEMA = `{
  "whyScoreIsHigh": string,        // direct answer to "why is this risk score/level what it is"
  "contributingFactors": string[], // each concrete signal from CONTEXT that fed into the score, one per entry
  "riskSeverity": string,          // one of: "Low", "Medium", "High", "Critical"
  "businessImpact": string,
  "technicalImpact": string,
  "recommendedRemediation": string[],
  "assumptions": string[]          // required by NO_HALLUCINATION_CLAUSE - empty array if nothing was missing
}`;

/**
 * Feature 2 (AI Threat Explanation). Built by aiExplanationService.js from a real ThreatScan/
 * DLPScan/File/SecurityEvent record, cross-linked with File metadata, DLP findings, Threat
 * Intelligence/MITRE mapping, and relevant SIEM events.
 * @param {object} context
 * @returns {string}
 */
export function buildThreatExplanationPrompt(context) {
  return [
    SYSTEM_PREAMBLE,
    "",
    "A security detection fired for a file or event belonging to this user. Explain it to them " +
      "the way a senior security analyst would explain an alert to both a non-expert account " +
      "owner (business impact) and a technical reader (technical impact): clear, calm, specific " +
      "to the facts given, and actionable.",
    "",
    NO_HALLUCINATION_CLAUSE,
    "",
    formatContextBlock(context),
    "",
    JSON_ONLY_CLAUSE,
    THREAT_EXPLANATION_SCHEMA
  ].join("\n");
}

/**
 * Feature 4 (AI Risk Explanation). Same context shape as buildThreatExplanationPrompt (built by
 * aiExplanationService.js's shared context-gathering pipeline), but asks specifically why the
 * risk score/level is what it is and what contributed to it, rather than a full incident
 * narrative.
 * @param {object} context
 * @returns {string}
 */
export function buildRiskExplanationPrompt(context) {
  return [
    SYSTEM_PREAMBLE,
    "",
    "The user is looking at a risk score/risk level for a file and clicked \"Explain\". Answer " +
      "specifically why the score/level is what it is, breaking down the contributing factors " +
      "from CONTEXT one by one, then the severity, impact, and remediation.",
    "",
    NO_HALLUCINATION_CLAUSE,
    "",
    formatContextBlock(context),
    "",
    JSON_ONLY_CLAUSE,
    RISK_EXPLANATION_SCHEMA
  ].join("\n");
}

const INCIDENT_SUMMARY_NARRATIVE_SCHEMA = `{
  "executiveSummary": string,      // 2-4 sentence narrative summary of the period covered by STATS, for a non-technical stakeholder
  "overallSecurityHealth": string, // one short paragraph characterizing overall posture given the real numbers
  "recommendations": string[]      // concrete, prioritized next steps grounded in the specific numbers in STATS
}`;

/**
 * Feature 3 (AI Incident Summary). Built by services/ai/reportGenerator.js from real, already-
 * computed statistics (never asks Gemini to invent or recompute a number - only to narrate what
 * the real STATS block already says, which is why this prompt is explicit that STATS is ground
 * truth and must be treated as complete/authoritative for the period it covers).
 * @param {object} stats
 * @returns {string}
 */
export function buildIncidentSummaryPrompt(stats) {
  return [
    SYSTEM_PREAMBLE,
    "",
    "Write the narrative portion of a security incident summary report for an executive " +
      "audience. The STATS block below is real, already-computed data - your job is only to " +
      "narrate and interpret it, never to invent additional figures or events not present in it.",
    "",
    NO_HALLUCINATION_CLAUSE,
    "",
    `STATS (JSON):\n${JSON.stringify(stats, null, 2)}`,
    "",
    JSON_ONLY_CLAUSE,
    INCIDENT_SUMMARY_NARRATIVE_SCHEMA
  ].join("\n");
}

/**
 * Feature 1 (AI Security Assistant Q&A). Built by chatService.js from whichever domain summaries
 * contextBuilder.js determined were relevant to the question - never the full dataset, so the
 * model only ever sees what's actually pertinent (and what's missing/restricted is visible to it
 * as such, not silently absent).
 * @param {string} question
 * @param {object} context - shape: { sectionsIncluded: string[], ...domainSummaries }
 * @returns {string}
 */
export function buildSecurityAssistantPrompt(question, context) {
  return [
    SYSTEM_PREAMBLE,
    "",
    "Answer the user's question below using only the real data in the CONTEXT block. This is a " +
      "conversational answer, not a report - be concise and direct, the way a security analyst " +
      "would answer a colleague's Slack message.",
    "",
    NO_HALLUCINATION_CLAUSE,
    'If a section the question needs is absent from CONTEXT or marked "restricted", tell the ' +
      "user plainly that you don't have access to that data (e.g. admin-only data requested by a " +
      "non-admin) instead of guessing an answer.",
    "",
    `QUESTION: ${question}`,
    "",
    formatContextBlock(context),
    "",
    "Respond in plain text (no JSON, no markdown code fences). A few short paragraphs or a short " +
      "bulleted list is fine if it aids clarity."
  ].join("\n");
}
