/**
 * AI Security Assistant: the only file in the codebase that talks to Gemini's REST API. Every
 * other AI service (aiExplanationService.js, chatService.js, and later reportGenerator.js) calls
 * generateContent() here rather than making its own HTTP call - same single-responsibility
 * convention as services/threatIntel/providers/*.js, one file per external provider.
 *
 * Entirely optional, same graceful-degradation shape as services/virusTotalLookup.js: if
 * GEMINI_API_KEY isn't set, callers get { status: "skipped" } immediately, no error thrown, no
 * network call attempted. Uses Node's built-in fetch (no axios/SDK dependency added).
 */
const GEMINI_HOST = "https://generativelanguage.googleapis.com";
const GEMINI_TIMEOUT_MS = 15000;
const DEFAULT_MODEL = "gemini-1.5-flash";

/**
 * @param {string} prompt - the fully-assembled prompt string (built by a services/ai/promptTemplates.js function)
 * @param {{ model?: string }} [options]
 * @returns {Promise<{status: "ok", text: string} | {status: "skipped"} | {status: "error", message: string}>}
 */
export async function generateContent(prompt, options = {}) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return { status: "skipped" };
  }

  const model = options.model || process.env.GEMINI_MODEL || DEFAULT_MODEL;
  const url = `${GEMINI_HOST}/v1beta/models/${model}:generateContent?key=${apiKey}`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), GEMINI_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ role: "user", parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.2, maxOutputTokens: 2048 }
      }),
      signal: controller.signal
    });

    if (!response.ok) {
      const body = await response.text().catch(() => "");
      return { status: "error", message: `Gemini API returned status ${response.status}: ${body.slice(0, 300)}` };
    }

    const data = await response.json();
    const text = data?.candidates?.[0]?.content?.parts?.map((p) => p.text || "").join("") || "";
    if (!text) {
      return { status: "error", message: "Gemini response contained no text" };
    }

    return { status: "ok", text };
  } catch (err) {
    if (err?.name === "AbortError") {
      return { status: "error", message: "Gemini request timed out" };
    }
    return { status: "error", message: err?.message || "Gemini request failed" };
  } finally {
    clearTimeout(timeout);
  }
}
