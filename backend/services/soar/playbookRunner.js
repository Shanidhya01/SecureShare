/**
 * Phase 8 (SOAR): executes a playbook's ordered steps against a triggering event. Accepts a
 * plain `{steps: [{type, params, continueOnFailure}]}` shape so both a Playbook document and a
 * rule's inline `actions` array (wrapped as an ad-hoc playbook) can be run through the same code
 * path - see soarEngine.js.
 *
 * `handlers` is injectable (defaults to the real ACTION_HANDLERS registry) so tests can supply
 * stub handlers without touching Mongo, mirroring this repo's existing dependency-injection-free-
 * but-still-testable style (e.g. dlpEngine.js's DETECTORS iteration).
 */
import { ACTION_HANDLERS } from "./actions/index.js";

export async function runPlaybook({ steps = [] }, event, context = {}, handlers = ACTION_HANDLERS) {
  const results = [];
  let hadFailure = false;

  for (const step of steps) {
    const handler = handlers[step.type];
    const start = Date.now();

    if (!handler) {
      results.push({ type: step.type, params: step.params, success: false, detail: "Unknown action type", durationMs: 0 });
      hadFailure = true;
      if (step.continueOnFailure === false) break;
      continue;
    }

    try {
      const outcome = await handler(step.params || {}, event, context);
      results.push({
        type: step.type,
        params: step.params,
        success: !!outcome?.success,
        detail: outcome?.detail || "",
        durationMs: Date.now() - start
      });
      if (!outcome?.success) {
        hadFailure = true;
        if (step.continueOnFailure === false) break;
      }
    } catch (err) {
      results.push({ type: step.type, params: step.params, success: false, detail: err.message, durationMs: Date.now() - start });
      hadFailure = true;
      if (step.continueOnFailure === false) break;
    }
  }

  const allRan = results.length === steps.length;
  const allSucceeded = results.every((r) => r.success);
  const status = allSucceeded && allRan ? "completed" : hadFailure && results.some((r) => r.success) ? "partial" : "failed";

  return { results, status };
}
