/**
 * Phase 8 (SOAR) orchestrator - the single entry point called from
 * backend/services/siem/siemLogger.js right after every SecurityEvent is persisted and
 * correlated. Flow: match enabled AutomationRules against the event, run each matched rule's
 * playbook (in priority order), record an AutomationExecution, update any correlated Incident,
 * and emit PLAYBOOK_ and AUTOMATION_ SIEM events for the response itself.
 *
 * Recursion guard: playbook actions (notifyUser, generateSiemEvent, etc.) call logSecurityEvent
 * themselves, which would re-enter this function. Every event this engine or its actions produce
 * carries category "AUTOMATION" (see eventCatalog.js), so any such event is ignored at the top of
 * this function - automation never triggers automation on itself.
 */
import AutomationRule from "../../models/AutomationRule.js";
import AutomationExecution from "../../models/AutomationExecution.js";
import Incident from "../../models/Incident.js";
import { matchRules } from "./ruleMatcher.js";
import { runPlaybook } from "./playbookRunner.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

async function resolvePlaybook(rule) {
  if (rule.playbookId) {
    const Playbook = (await import("../../models/Playbook.js")).default;
    const playbook = await Playbook.findById(rule.playbookId);
    if (playbook?.enabled !== false && playbook) return { steps: playbook.steps, playbookDoc: playbook };
  }
  return { steps: rule.actions || [], playbookDoc: null };
}

export async function runSoarEngine(event) {
  if (!event || event.category === "AUTOMATION") return; // guard against self-triggering

  try {
    const rules = await AutomationRule.find({ enabled: true }).lean();
    const matched = matchRules(event, rules);
    if (matched.length === 0) return;

    for (const rule of matched) {
      const start = Date.now();
      const { steps, playbookDoc } = await resolvePlaybook(rule);

      await logSecurityEvent({
        owner: event.owner,
        type: "automation_triggered",
        message: `Automation rule "${rule.name}" triggered by ${rule.trigger}`,
        file: event.file,
        filename: event.filename,
        metadata: { ruleId: rule._id, ruleName: rule.name, trigger: rule.trigger }
      });

      if (playbookDoc) {
        await logSecurityEvent({
          owner: event.owner,
          type: "playbook_started",
          message: `Playbook "${playbookDoc.name}" started`,
          file: event.file,
          filename: event.filename,
          metadata: { playbookId: playbookDoc._id, playbookName: playbookDoc.name }
        });
      }

      const { results, status } = await runPlaybook({ steps }, event);
      const durationMs = Date.now() - start;

      const execution = await AutomationExecution.create({
        owner: event.owner,
        rule: rule._id,
        ruleName: rule.name,
        playbook: playbookDoc?._id || null,
        playbookName: playbookDoc?.name || null,
        triggerEvent: event._id,
        trigger: rule.trigger,
        actionsExecuted: results,
        status,
        durationMs,
        result: `${results.filter((r) => r.success).length}/${results.length} action(s) succeeded`
      });

      await logSecurityEvent({
        owner: event.owner,
        type: status === "failed" ? "playbook_failed" : "playbook_completed",
        message: playbookDoc
          ? `Playbook "${playbookDoc.name}" ${status}`
          : `Automation rule "${rule.name}" actions ${status}`,
        file: event.file,
        filename: event.filename,
        metadata: { executionId: execution._id, status, durationMs }
      });

      if (event.correlationId) {
        await Incident.findByIdAndUpdate(event.correlationId, {
          automationStatus: status === "failed" ? "failed" : "completed",
          $push: {
            executedPlaybooks: {
              playbookId: playbookDoc?._id || null,
              playbookName: playbookDoc?.name || rule.name,
              executionId: execution._id,
              ranAt: new Date()
            },
            actionTimeline: {
              $each: results.map((r) => ({ type: r.type, success: r.success, detail: r.detail, timestamp: new Date() }))
            }
          },
          responseDurationMs: durationMs
        }).catch((err) => console.error("Failed to update incident with automation result:", err));

        execution.incident = event.correlationId;
        await execution.save().catch(() => {});
      }
    }
  } catch (err) {
    console.error("SOAR engine error:", err);
  }
}
