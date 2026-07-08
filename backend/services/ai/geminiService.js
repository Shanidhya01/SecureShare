/**
 * AI Security Assistant: the only file in the codebase that talks to the LLM provider. Every
 * other AI service (aiExplanationService.js, chatService.js, reportGenerator.js) calls
 * generateContent() here rather than making its own HTTP call - same single-responsibility
 * convention as services/threatIntel/providers/*.js, one file per external provider.
 *
 * Currently backed by OpenRouter's OpenAI-compatible chat completions API (kept in this file
 * despite the "gemini" name to avoid touching every import site across the AI module - the
 * exported generateContent(prompt) contract is provider-agnostic: {status, text} in, callers
 * never know or care which provider is behind it). Swapping providers again later only means
 * editing the fetch call below.
 *
 * Entirely optional, same graceful-degradation shape as services/virusTotalLookup.js: if
 * OPENROUTER_API_KEY isn't set, callers get { status: "skipped" } immediately, no error thrown,
 * no network call attempted. Uses Node's built-in fetch (no axios/SDK dependency added).
 */
const OPENROUTER_HOST = "https://openrouter.ai/api/v1";
const REQUEST_TIMEOUT_MS = 15000;
// Free model on OpenRouter. Override via OPENROUTER_MODEL without a code change if this one is
// retired/renamed or you want a different model - https://openrouter.ai/models lists what's
// currently available (filter by "Free" to stay on no-cost models).
const DEFAULT_MODEL = "openai/gpt-oss-120b:free";

/**
 * @param {string} prompt - the fully-assembled prompt string (built by a services/ai/promptTemplates.js function)
 * @param {{ model?: string }} [options]
 * @returns {Promise<{status: "ok", text: string} | {status: "skipped"} | {status: "error", message: string}>}
 */
export async function generateContent(prompt, options = {}) {
  const apiKey = process.env.OPENROUTER_API_KEY;
  if (!apiKey) {
    return { status: "skipped" };
  }

  const model = options.model || process.env.OPENROUTER_MODEL || DEFAULT_MODEL;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(`${OPENROUTER_HOST}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model,
        messages: [{ role: "user", content: prompt }],
        temperature: 0.2,
        max_tokens: 2048
      }),
      signal: controller.signal
    });

    if (!response.ok) {
      if (response.status === 429) {
        // Free-tier OpenRouter quota (per-minute or per-day) exceeded - a real, expected
        // condition, not a bug. Surface something a non-technical user can act on instead of the
        // provider's raw error JSON.
        return {
          status: "error",
          message: "AI Security Assistant has hit its request limit for now. Please try again in a minute, or check your OpenRouter plan's quota."
        };
      }
      const body = await response.text().catch(() => "");
      return { status: "error", message: `AI provider returned status ${response.status}: ${body.slice(0, 300)}` };
    }

    const data = await response.json();
    const text = data?.choices?.[0]?.message?.content || "";
    if (!text) {
      return { status: "error", message: "AI provider response contained no text" };
    }

    return { status: "ok", text };
  } catch (err) {
    if (err?.name === "AbortError") {
      return { status: "error", message: "AI provider request timed out" };
    }
    return { status: "error", message: err?.message || "AI provider request failed" };
  } finally {
    clearTimeout(timeout);
  }
}
